# Linux guest profiles for IntroVirt (SecTepe)

The native Linux guest model (see `docs/introvirt-linux-port.md`) resolves
kernel symbols and struct member offsets from an **offline-generated
profile** instead of an in-image PDB. This directory holds the generator.

## What a profile contains

A compact JSON (`sectepe-linux-isf/1`) with exactly what the model walks:

```json
{
  "format": "sectepe-linux-isf/1",
  "metadata": { "arch": "x86_64", "source_producer": "dwarf2json" },
  "symbols": { "init_task": 18446744071578834944, "_text": ..., "entry_SYSCALL_64": ... },
  "types":   { "task_struct": { "comm": 1544, "pid": 1232, "tasks": 1080, "mm": 1096 }, ... },
  "sizes":   { "task_struct": 9216, ... }
}
```

Symbol addresses are **link-time** addresses; the live KASLR slide is
applied at runtime by `LinuxKernel`.

## Generating one

1. Get the **uncompressed `vmlinux`** with DWARF for the guest kernel
   (the `-dbg`/`-debuginfo` package, or build output). The compressed
   `vmlinuz` on `/boot` does *not* carry DWARF.

2. Produce a Volatility3 ISF with
   [`dwarf2json`](https://github.com/volatilityfoundation/dwarf2json):

   ```bash
   dwarf2json linux --elf vmlinux > vmlinux.isf.json
   ```

3. Downselect + validate to the SecTepe profile:

   ```bash
   python3 generate_isf.py --in vmlinux.isf.json \
       --out ~/.introvirt/profiles/linux-$(uname -r)-x86_64.json
   ```

   `generate_isf.py` **fails loudly** if the kernel's DWARF is missing any
   symbol or struct member the model depends on (the `REQUIRED_SYMBOLS` /
   `REQUIRED_TYPES` manifest at the top of the script) — so an incomplete
   profile is caught on the build host, not on a live detonation. Use
   `--check` to validate without writing.

## Versioning notes

- The manifest tolerates kernel-version drift where the layout genuinely
  changed: the pre-6.1 `mm_struct.mmap` VMA list **or** the >=6.1
  `mm_struct.mm_mt` maple tree satisfies the memory-map requirement
  (`OPTIONAL_MEMBERS` in the script).
- One profile per guest kernel release; the model selects it via
  `LinuxProfile::load_for_release(release, arch)`.
