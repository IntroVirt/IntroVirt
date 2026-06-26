#!/usr/bin/env python3
"""@example ivcallmon.py

API call monitor (ivcallmon).

Sets breakpoints on specified module!symbol patterns. Walks the process VAD tree
to find modules and uses PDB for symbol resolution (same as C++ ivcallmon).
Optional return breakpoints use read_guest_uint64 to read the return address from RSP.

Usage:
  sudo ivcallmon_py DOMAIN --procname NAME [SYMBOL ...]
  sudo python3 -m pyintrovirt.tools.ivcallmon DOMAIN --procname NAME 'ntdll!Nt*'

Example:
  sudo ivcallmon_py myvm --procname notepad.exe 'ntdll!NtCreateFile' 'ntdll!Nt*'

Default symbol set is ntdll!Nt* if none provided.

Requires root and IntroVirt-patched hypervisor.
"""

import argparse
import functools
import sys
import threading
import traceback
from dataclasses import dataclass, field
from typing import Any

import introvirt  # pylint: disable=import-error

from pyintrovirt import OS, VMI, Event, EventType, SystemCallIndex, nt_success


class BreakpointHandler(introvirt.BreakpointCallback):  # pylint: disable=too-few-public-methods
    """Handle breakpoint hits and optionally install return breakpoints."""

    def __init__(self, domain, name: str, pid: int, return_bp: bool):
        super().__init__()
        self._domain = domain
        self._name = name
        self._pid = pid
        self._return_bp = return_bp
        self._return_breakpoint = None

    def breakpoint_hit(self, e: Any) -> Any:
        """Called from C++ when a breakpoint fires."""
        if e.task().pid() != self._pid:
            return
        task = e.task()
        vcpu = e.vcpu()
        regs = vcpu.registers()
        print(f"[{task.pid()}:{task.tid()}] {task.process_name()}")
        print(f"    Hit breakpoint {self._name}")
        sys.stdout.flush()
        if self._return_bp and self._return_breakpoint is None:
            try:
                rsp = regs.rsp()
                ret_addr = introvirt.read_guest_uint64(self._domain, vcpu, rsp)
                if ret_addr != 0:
                    ret_handler = ReturnBreakpointHandler(self._domain, self._name, task.tid(), rsp + 8)
                    self._return_breakpoint = introvirt.create_breakpoint_holder(self._domain, vcpu, ret_addr, ret_handler)
            except Exception as exc:  # pylint: disable=broad-exception-caught
                print(f"    (return breakpoint skipped: {exc})", file=sys.stderr)


class ReturnBreakpointHandler(introvirt.BreakpointCallback):  # pylint: disable=too-few-public-methods
    """Handle return-address breakpoints for a prior API call."""

    def __init__(self, domain, name: str, tid: int, expected_rsp: int):
        super().__init__()
        self._domain = domain
        self._name = name
        self._tid = tid
        self._expected_rsp = expected_rsp

    def breakpoint_hit(self, e: Any) -> Any:
        """Called from C++ when a return breakpoint fires."""
        if e.task().tid() != self._tid:
            return
        if e.vcpu().registers().rsp() != self._expected_rsp:
            return
        task = e.task()
        print(f"[{task.pid()}:{task.tid()}] {task.process_name()}")
        print(f"    Return hit for {self._name}")
        sys.stdout.flush()


def _filename_ends_with_dll(filename: str, dll: str) -> bool:
    """Case-insensitive check if filename ends with dll (e.g. ntdll.dll)."""
    fn, d = filename.lower().replace("/", "\\"), dll.lower()
    if not d.endswith(".dll"):
        d = d + ".dll"
    return fn.endswith(d)


def _iv_event(event: Event) -> introvirt.Event:
    """Return the underlying introvirt event."""
    return event._iv_event  # pylint: disable=protected-access


def _iv_domain(vmi: VMI) -> introvirt.Domain:
    """Return the underlying introvirt domain."""
    return vmi._attached_domain()._attached()  # pylint: disable=protected-access


@dataclass
class CallMonitorConfig:
    """Static configuration for ivcallmon breakpoint setup."""

    domain: introvirt.Domain
    requested_symbols: dict
    requested_dlls: set
    return_bp: bool


@dataclass
class CallMonitorState:  # pylint: disable=too-few-public-methods
    """Mutable state shared across ivcallmon event callbacks."""

    config: CallMonitorConfig
    breakpoints: list = field(default_factory=list)
    found_dlls: set = field(default_factory=set)
    all_symbols_resolved: bool = False
    initial_check_done: bool = False
    lock: threading.Lock = field(default_factory=threading.Lock)


def _create_breakpoints_for_module(  # pylint: disable=too-many-arguments,too-many-positional-arguments
    state: CallMonitorState,
    vcpu: introvirt.Vcpu,
    pid: int,
    base: int,
    filename: str,
    matched_dll: str,
) -> bool:
    """Resolve symbols and create breakpoints for one mapped module. Returns True if all DLLs are done."""
    module_name = matched_dll[:-4] if matched_dll.lower().endswith(".dll") else matched_dll
    patterns = state.config.requested_symbols.get(module_name)
    if not patterns:
        return False

    try:
        print(f"Resolving symbols for {filename} with patterns {patterns}")
        symbol_list = introvirt.resolve_symbols_via_pdb(state.config.domain, vcpu, base, patterns)
        print(f"Resolved symbols: {symbol_list}")
    except Exception:  # pylint: disable=broad-exception-caught
        traceback.print_exc(file=sys.stderr)
        return False

    for addr, name in symbol_list:
        print(f"Creating breakpoint for {module_name}!{name} at {addr}")
        handler = BreakpointHandler(state.config.domain, f"{module_name}!{name}", pid, state.config.return_bp)
        bp = introvirt.create_breakpoint_holder(state.config.domain, vcpu, addr, handler)
        if bp is not None:
            state.breakpoints.append((handler, bp))
    state.found_dlls.add(matched_dll)
    return len(state.found_dlls) >= len(state.config.requested_dlls)


def _set_breakpoints(state: CallMonitorState, vmi: VMI, event: Event):
    with state.lock:
        if state.all_symbols_resolved:
            return
        iv_event = _iv_event(event)
        if not isinstance(iv_event, introvirt.WindowsEvent):
            return
        vcpu = event.vcpu
        pid = event.pid
        modules = introvirt.get_executable_mapped_modules(iv_event)
        for base, filename in modules:
            matched_dll = None
            for dll in state.config.requested_dlls:
                if _filename_ends_with_dll(filename, dll):
                    matched_dll = dll
                    break
            if matched_dll is None or matched_dll in state.found_dlls:
                continue
            if _create_breakpoints_for_module(state, vcpu, pid, base, filename, matched_dll):
                state.all_symbols_resolved = True
                vmi.intercept_system_calls(False)
                return


def handle_syscall(_vmi: VMI, event: Event, *, state: CallMonitorState):
    """Handle syscall events to trigger initial breakpoint setup."""
    if event.syscall_index == SystemCallIndex.NtMapViewOfSection:
        event.hook_return(True)
    if not state.initial_check_done:
        state.initial_check_done = True
        print("Initial syscall event, setting breakpoints")
        _set_breakpoints(state, _vmi, event)


def handle_sysret(vmi: VMI, event: Event, *, state: CallMonitorState):
    """Handle syscall return events after module mapping."""
    if event.syscall_index == SystemCallIndex.NtMapViewOfSection:
        handler = event.get_syscall_handler()
        result = event.get_result()
        if handler is not None and result is not None and nt_success(result):
            print("NtMapViewOfSection succeeded, setting breakpoints")
            _set_breakpoints(state, vmi, event)
    if state.all_symbols_resolved:
        vmi.intercept_system_calls(False)


def handle_cr_write(vmi: VMI, event: Event, *, state: CallMonitorState):
    """Handle CR3 write events to trigger initial breakpoint setup."""
    if _iv_event(event).cr().index() != 3:
        return
    if not state.initial_check_done:
        state.initial_check_done = True
        vmi.intercept_cr_writes(3, False)
        print("Initial CR3 write event, turning off CR3 monitoring")
        _set_breakpoints(state, vmi, event)


def main():
    """Entry point for ivcallmon."""
    parser = argparse.ArgumentParser(description="Monitor API calls via breakpoints (ivcallmon clone). VAD + PDB symbol resolution.")
    parser.add_argument("domain", metavar="DOMAIN", help="Domain name or ID")
    parser.add_argument("--procname", metavar="NAME", required=True, help="Process name filter")
    parser.add_argument(
        "--no-return",
        action="store_true",
        help="Do not set return breakpoints",
    )
    parser.add_argument(
        "symbols",
        nargs="*",
        metavar="SYMBOL",
        help="Symbols as module!name or module!pattern (default: ntdll!Nt*)",
    )
    args = parser.parse_args()

    symbols = [s.strip().lower() for s in args.symbols] if args.symbols else ["ntdll!nt*"]
    requested_symbols = {}
    requested_dlls = set()
    for sym in symbols:
        if "!" not in sym:
            print(f"Invalid symbol (expected module!name): {sym}", file=sys.stderr)
            return 1
        mod, pat = sym.split("!", 1)
        if mod.endswith(".dll"):
            mod = mod[:-4]
        requested_symbols.setdefault(mod, []).append(pat)
        dll = mod + ".dll"
        requested_dlls.add(dll)

    rc = 1

    try:
        with VMI(args.domain) as vmi:
            if vmi.guest_os() != OS.Windows:
                print("ivcallmon only supports Windows guests", file=sys.stderr)
                return rc

            print(f"Guest OS: {vmi.guest_os().name}")

            vmi.filter_task(name=args.procname)
            vmi.filter_system_calls([SystemCallIndex.NtMapViewOfSection])
            vmi.intercept_system_calls(True)
            vmi.intercept_cr_writes(3, True)

            state = CallMonitorState(
                CallMonitorConfig(
                    _iv_domain(vmi),
                    requested_symbols,
                    requested_dlls,
                    return_bp=not args.no_return,
                )
            )

            vmi.register_callback(
                EventType.EVENT_FAST_SYSCALL,
                functools.partial(handle_syscall, state=state),
            )
            vmi.register_callback(
                EventType.EVENT_FAST_SYSCALL_RET,
                functools.partial(handle_sysret, state=state),
            )
            vmi.register_callback(
                EventType.EVENT_CR_WRITE,
                functools.partial(handle_cr_write, state=state),
            )
            vmi.poll(blocking=True)
    except Exception:  # pylint: disable=broad-exception-caught
        traceback.print_exc()
        return rc

    return 0


if __name__ == "__main__":
    sys.exit(main())
