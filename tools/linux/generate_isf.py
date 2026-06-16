#!/usr/bin/env python3
# Copyright 2026 SecTepe.
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#         http://www.apache.org/licenses/LICENSE-2.0
"""Generate a compact SecTepe Linux ISF profile for IntroVirt.

IntroVirt's Windows guest model resolves kernel symbols + struct member
offsets from the PDB embedded in the kernel PE image. Linux has no PDB, so
the native Linux guest model (see docs/introvirt-linux-port.md) instead
loads an offline-generated profile: symbol addresses + the handful of
struct member offsets the model walks (task_struct, mm_struct,
vm_area_struct, ...).

Rather than re-parse DWARF here, this tool consumes a Volatility3-style ISF
JSON (produced by `dwarf2json linux --elf vmlinux`) and *downselects* it to
exactly the symbols and type members IntroVirt needs, emitting a small,
flat, fast-to-parse JSON that the C++ ``LinuxProfile`` loader reads.

Keeping a curated REQUIRED manifest here means a profile that is missing
something the model depends on fails loudly at generation time (on the
build host) instead of at introspection time (on a live detonation).

Usage:
    generate_isf.py --in vmlinux.isf.json --out linux-<ver>-<arch>.json
    generate_isf.py --in vmlinux.isf.json --check        # validate only
"""
from __future__ import annotations

import argparse
import json
import sys
from typing import Dict, List, Tuple

# Schema version of the *emitted* SecTepe profile (not the Vol3 input).
PROFILE_FORMAT = "sectepe-linux-isf/1"

# Kernel symbols the Linux guest model resolves. `_text`/`_stext` anchor the
# KASLR-slide computation against the live MSR_LSTAR / banner; `init_task` is
# the head of the task list; the syscall entry is the syscall-hook target.
REQUIRED_SYMBOLS: Tuple[str, ...] = (
    "init_task",
    "_text",
    "_stext",
    "entry_SYSCALL_64",
    "current_task",        # per-CPU: resolve the running task from GS base
    "linux_banner",        # "Linux version ..." — confirms guest is Linux
    "page_offset_base",    # direct-map base (KASLR): KVA->PA for a process pgd
)

# Symbols the model uses opportunistically — extracted if present, but their
# absence does NOT fail profile generation (kernel-version-dependent names).
OPTIONAL_SYMBOLS: Tuple[str, ...] = (
    # The kernel's top-level page table (`swapper_pg_dir` on older kernels).
    # Its *physical* address is a STABLE kernel-mapping CR3 — the model
    # translates this VA once at detection to read kernel memory from event
    # handlers without depending on whichever (possibly short-lived) process
    # CR3 happened to be live at attach.
    "init_top_pgt",
    "init_level4_pgt",     # pre-4.13 name
)

# Struct member offsets the model walks. Keep this in lockstep with the C++
# LinuxKernelImpl reads; adding a read there means adding the member here.
REQUIRED_TYPES: Dict[str, Tuple[str, ...]] = {
    "task_struct": ("tasks", "pid", "tgid", "comm", "mm", "active_mm",
                    "real_parent", "parent"),
    "mm_struct": ("pgd", "mmap", "mm_mt"),       # mm_mt: maple-tree on >=6.1
    "vm_area_struct": ("vm_start", "vm_end", "vm_next", "vm_file", "vm_flags"),
    "list_head": ("next", "prev"),
}

# Members that genuinely vary by kernel version — absence is tolerated (the
# model picks whichever layout the running kernel exposes). Everything else
# in REQUIRED_TYPES must be present.
OPTIONAL_MEMBERS = {
    ("mm_struct", "mmap"),     # removed in favour of mm_mt on >= 6.1
    ("mm_struct", "mm_mt"),    # absent on < 6.1
    ("vm_area_struct", "vm_next"),  # gone with the maple-tree rework
    ("task_struct", "active_mm"),
    ("task_struct", "parent"),
}


def _member_offset(field: dict) -> int:
    """Vol3 ISF stores a member as {"offset": N, "type": {...}}."""
    return int(field["offset"])


def _flatten_fields(tinfo: dict, src_types: Dict[str, dict],
                    base: int = 0, _seen: frozenset = frozenset()) -> Dict[str, int]:
    """Return {member_name: absolute_offset} for a struct, hoisting members of
    anonymous nested struct/union aggregates into the parent namespace.

    Modern kernels wrap the body of an aggregate in an anonymous struct for
    layout/randomisation reasons — e.g. 5.15 ``mm_struct`` keeps ``pgd``,
    ``mmap`` etc. inside an unnamed inner struct at offset 0, leaving only
    ``cpu_bitmap`` + the anonymous field at the top level. dwarf2json mirrors
    this nesting, so a flat ``fields`` scan misses every real member. We
    recurse into anonymous aggregate members, adding their base offset so the
    hoisted offsets stay absolute from the outer struct base (what the C++
    LinuxProfile loader expects)."""
    flat: Dict[str, int] = {}
    for name, field in tinfo.get("fields", {}).items():
        off = base + _member_offset(field)
        ftype = field.get("type", {})
        is_anon = bool(field.get("anonymous")) and ftype.get("kind") in ("struct", "union")
        if is_anon:
            tname = ftype.get("name")
            if tname and tname not in _seen:
                inner = src_types.get(tname)
                if inner is not None:
                    for m, o in _flatten_fields(inner, src_types, off,
                                                _seen | {tname}).items():
                        flat.setdefault(m, o)
                    continue
        # Named members win over any same-named hoisted member.
        flat[name] = off
    return flat


def build_profile(vol3: dict) -> dict:
    """Downselect a Volatility3 ISF dict to the SecTepe Linux profile."""
    src_symbols = vol3.get("symbols", {})
    src_types = vol3.get("user_types", {})
    src_meta = vol3.get("metadata", {})

    symbols: Dict[str, int] = {}
    for name in REQUIRED_SYMBOLS + OPTIONAL_SYMBOLS:
        entry = src_symbols.get(name)
        if entry is not None and entry.get("address") is not None:
            symbols[name] = int(entry["address"])

    types: Dict[str, Dict[str, int]] = {}
    sizes: Dict[str, int] = {}
    for struct, members in REQUIRED_TYPES.items():
        tinfo = src_types.get(struct)
        if tinfo is None:
            continue
        fields = _flatten_fields(tinfo, src_types)
        member_offsets: Dict[str, int] = {}
        for member in members:
            if member in fields:
                member_offsets[member] = fields[member]
        types[struct] = member_offsets
        if tinfo.get("size") is not None:
            sizes[struct] = int(tinfo["size"])

    # Pull a linux-banner-ish identity through if the input carries it.
    producer = src_meta.get("producer", {})
    linux_meta = src_meta.get("linux", {})
    return {
        "format": PROFILE_FORMAT,
        "metadata": {
            "arch": linux_meta.get("arch") or src_meta.get("arch") or "x86_64",
            "kernel": (linux_meta.get("kernel") or {}).get("symbols")
            if isinstance(linux_meta.get("kernel"), dict) else None,
            "source_producer": producer.get("name"),
        },
        "symbols": symbols,
        "types": types,
        "sizes": sizes,
    }


def validate(profile: dict) -> List[str]:
    """Return a list of human-readable problems; empty == complete."""
    problems: List[str] = []
    for name in REQUIRED_SYMBOLS:
        if name not in profile.get("symbols", {}):
            problems.append(f"missing symbol: {name}")
    for struct, members in REQUIRED_TYPES.items():
        tmembers = profile.get("types", {}).get(struct)
        if tmembers is None:
            problems.append(f"missing type: {struct}")
            continue
        for member in members:
            if member in tmembers:
                continue
            if (struct, member) in OPTIONAL_MEMBERS:
                continue
            problems.append(f"missing member: {struct}.{member}")
    # At least one of the two mm-region layouts (legacy mmap list OR maple
    # tree) must be resolvable, else the model can't walk the memory map.
    mm = profile.get("types", {}).get("mm_struct", {})
    if "mmap" not in mm and "mm_mt" not in mm:
        problems.append("mm_struct has neither mmap nor mm_mt (no VMA walk)")
    return problems


def main(argv: List[str]) -> int:
    ap = argparse.ArgumentParser(description=__doc__,
                                 formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--in", dest="infile", required=True,
                    help="Volatility3 ISF JSON (from dwarf2json)")
    ap.add_argument("--out", dest="outfile",
                    help="output SecTepe Linux profile JSON")
    ap.add_argument("--check", action="store_true",
                    help="validate completeness only; do not write output")
    args = ap.parse_args(argv)

    with open(args.infile, "r") as fh:
        vol3 = json.load(fh)

    profile = build_profile(vol3)
    problems = validate(profile)
    if problems:
        sys.stderr.write("INCOMPLETE Linux profile:\n")
        for p in problems:
            sys.stderr.write(f"  - {p}\n")
        return 2

    if args.check:
        sys.stderr.write("profile complete: %d symbols, %d types\n" % (
            len(profile["symbols"]), len(profile["types"])))
        return 0

    if not args.outfile:
        ap.error("--out is required unless --check is given")
    with open(args.outfile, "w") as fh:
        json.dump(profile, fh, indent=2, sort_keys=True)
    sys.stderr.write("wrote %s (%d symbols, %d types)\n" % (
        args.outfile, len(profile["symbols"]), len(profile["types"])))
    return 0


if __name__ == "__main__":
    raise SystemExit(main(sys.argv[1:]))
