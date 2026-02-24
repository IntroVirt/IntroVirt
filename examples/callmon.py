#!/usr/bin/env python3
"""IntroVirt Python example: API call monitor (ivcallmon clone).

Sets breakpoints on specified module!symbol patterns. Supports export-only
resolution when a module base is provided via --module-base. Optional return
breakpoints use read_guest_uint64 to read the return address from RSP.

Usage:
  python3 callmon.py DOMAIN --procname NAME --module-base MODULE=ADDRESS SYMBOL [SYMBOL ...]

Example:
  python3 callmon.py myvm --procname notepad.exe --module-base ntdll=0x7ff123400000 ntdll!NtCreateFile ntdll!Nt*

Requires root and IntroVirt-patched hypervisor.
"""
import argparse
import fnmatch
import signal
import sys
import threading

import introvirt

_domain = None


def _interrupt_listener():
    signal.pthread_sigmask(signal.SIG_UNBLOCK, [signal.SIGINT])
    while True:
        try:
            signal.sigwait([signal.SIGINT])
        except (ValueError, OSError):
            break
        d = _domain
        if d is not None:
            d.interrupt()


def wildcard_match(pattern: str, s: str) -> bool:
    """Match pattern (with * and ?) against s, case-insensitive."""
    pattern, s = pattern.lower(), s.lower()
    # Simple non-recursive * match
    if "*" not in pattern and "?" not in pattern:
        return pattern == s
    return fnmatch.fnmatch(s, pattern)


def resolve_export_symbols(domain, vcpu, module_base: int, module_name: str, patterns: list):
    """Resolve export names matching patterns at the given PE base. Returns list of (address, name)."""
    try:
        pe = introvirt.pe_from_address(domain, vcpu, module_base)
    except Exception:
        return []
    if pe is None:
        return []
    try:
        exp_dir = pe.export_directory()
        if exp_dir is None:
            return []
        results = []
        name_map = exp_dir.NameToExportMap()
        if name_map is None:
            return []
        for name, exp in name_map.items():
            for pat in patterns:
                if wildcard_match(pat, name):
                    addr_val = introvirt.pe_export_address_value(exp)
                    if addr_val != 0:
                        results.append((module_base + addr_val, name))
                    break
        return results
    finally:
        if pe is not None:
            # PE is returned as raw pointer; SWIG/newobject will delete when Python drops it
            pass


class BreakpointHandler(introvirt.BreakpointCallback):
    def __init__(self, domain, name: str, pid: int, return_bp: bool):
        super().__init__()
        self._domain = domain
        self._name = name
        self._pid = pid
        self._return_bp = return_bp
        self._return_breakpoint = None

    def breakpoint_hit(self, event):
        if event.task().pid() != self._pid:
            return
        task = event.task()
        vcpu = event.vcpu()
        regs = vcpu.registers()
        print(f"[{task.pid()}:{task.tid()}] {task.process_name()}")
        print(f"    Hit breakpoint {self._name}")
        sys.stdout.flush()
        if self._return_bp and self._return_breakpoint is None:
            try:
                rsp = regs.rsp()
                ret_addr = introvirt.read_guest_uint64(self._domain, vcpu, rsp)
                if ret_addr != 0:
                    ret_handler = ReturnBreakpointHandler(
                        self._domain, self._name, task.pid(), task.tid(), rsp + 8
                    )
                    self._return_breakpoint = introvirt.create_breakpoint(
                        self._domain, vcpu, ret_addr, ret_handler
                    )
            except Exception as e:
                print(f"    (return breakpoint skipped: {e})", file=sys.stderr)


class ReturnBreakpointHandler(introvirt.BreakpointCallback):
    def __init__(self, domain, name: str, pid: int, tid: int, expected_rsp: int):
        super().__init__()
        self._domain = domain
        self._name = name
        self._pid = pid
        self._tid = tid
        self._expected_rsp = expected_rsp

    def breakpoint_hit(self, event):
        if event.task().tid() != self._tid:
            return
        if event.vcpu().registers().rsp() != self._expected_rsp:
            return
        task = event.task()
        print(f"[{task.pid()}:{task.tid()}] {task.process_name()}")
        print(f"    Return hit for {self._name}")
        sys.stdout.flush()


class CallMonitor(introvirt.EventCallback):
    def __init__(self, domain, procname: str, module_bases: dict, symbols: list, return_bp: bool):
        super().__init__()
        self._domain = domain
        self._procname = procname
        self._module_bases = module_bases  # module_name -> base_address
        self._symbols = symbols  # list of "module!pattern"
        self._return_bp = return_bp
        self._breakpoints = []
        self._installed = False
        self._lock = threading.Lock()
        self._symbols_by_module = {}

    def set_symbols_by_module(self, symbols_by_module: dict):
        self._symbols_by_module = symbols_by_module

    def process_event(self, event):
        try:
            if event.type() == introvirt.EventType_EVENT_FAST_SYSCALL:
                self._handle_syscall(event)
            elif event.type() == introvirt.EventType_EVENT_FAST_SYSCALL_RET:
                self._handle_sysret(event)
        except Exception as e:
            print(f"process_event error: {e}", file=sys.stderr)
            import traceback
            traceback.print_exc(file=sys.stderr)

    def _handle_syscall(self, event):
        wevent = introvirt.WindowsEvent_from_event(event)
        if wevent is not None and wevent.syscall().index() == introvirt.SystemCallIndex_NtMapViewOfSection:
            wevent.syscall().hook_return(True)
        if not self._installed:
            self._installed = True
            self._install_breakpoints(event)

    def _handle_sysret(self, event):
        wevent = introvirt.WindowsEvent_from_event(event)
        if wevent is None:
            return
        if wevent.syscall().index() == introvirt.SystemCallIndex_NtMapViewOfSection:
            handler = wevent.syscall().handler()
            if handler is not None and handler.result().NT_SUCCESS():
                if not self._installed:
                    self._installed = True
                    self._install_breakpoints(event)

    def _install_breakpoints(self, event):
        task = event.task()
        vcpu = event.vcpu()
        pid = task.pid()
        for module_name, patterns in self._symbols_by_module.items():
            base = self._module_bases.get(module_name)
            if base is None:
                continue
            addrs = resolve_export_symbols(self._domain, vcpu, base, module_name, patterns)
            for addr, name in addrs:
                handler = BreakpointHandler(
                    self._domain, f"{module_name}!{name}", pid, self._return_bp
                )
                bp = introvirt.create_breakpoint(self._domain, vcpu, addr, handler)
                if bp is not None:
                    with self._lock:
                        self._breakpoints.append(bp)


def main():
    global _domain
    parser = argparse.ArgumentParser(
        description="Monitor API calls via breakpoints (ivcallmon clone). Export-only resolution."
    )
    parser.add_argument("domain", metavar="DOMAIN", help="Domain name or ID")
    parser.add_argument("--procname", metavar="NAME", required=True, help="Process name filter")
    parser.add_argument(
        "--module-base",
        metavar="MODULE=ADDRESS",
        action="append",
        dest="module_bases",
        default=[],
        help="Module base address (e.g. ntdll=0x7ff123400000). Can be repeated.",
    )
    parser.add_argument(
        "--no-return",
        action="store_true",
        help="Do not set return breakpoints",
    )
    parser.add_argument(
        "symbols",
        nargs="+",
        metavar="SYMBOL",
        help="Symbols as module!name or module!pattern (e.g. ntdll!NtCreateFile, ntdll!Nt*)",
    )
    args = parser.parse_args()

    module_bases = {}
    for s in args.module_bases:
        if "=" not in s:
            print("Invalid --module-base (expected MODULE=ADDRESS)", file=sys.stderr)
            return 1
        name, addr_str = s.split("=", 1)
        name = name.strip().lower()
        if name.endswith(".dll"):
            name = name[:-4]
        try:
            module_bases[name] = int(addr_str, 0)
        except ValueError:
            print(f"Invalid address: {addr_str}", file=sys.stderr)
            return 1

    symbols_by_module = {}
    for sym in args.symbols:
        sym = sym.strip().lower()
        if "!" not in sym:
            print(f"Invalid symbol (expected module!name): {sym}", file=sys.stderr)
            return 1
        mod, pat = sym.split("!", 1)
        if mod.endswith(".dll"):
            mod = mod[:-4]
        symbols_by_module.setdefault(mod, []).append(pat)

    for mod in symbols_by_module:
        if mod not in module_bases:
            print(f"No --module-base for module '{mod}'", file=sys.stderr)
            return 1

    try:
        hypervisor = introvirt.Hypervisor.instance()
    except Exception as e:
        print(f"Failed to get hypervisor: {e}", file=sys.stderr)
        return 1
    try:
        _domain = hypervisor.attach_domain(args.domain)
    except Exception as e:
        print(f"Failed to attach to domain: {e}", file=sys.stderr)
        return 1
    if not _domain.detect_guest():
        print("Failed to detect guest OS", file=sys.stderr)
        return 1

    _domain.task_filter().add_name(args.procname)
    guest = _domain.guest()
    if guest is not None and guest.os() == introvirt.OS_Windows:
        win_guest = introvirt.WindowsGuest_from_guest(guest)
        if win_guest is not None:
            _domain.system_call_filter().clear()
            _domain.system_call_filter().set_64(
                introvirt.SystemCallIndex_NtMapViewOfSection, True
            )
            _domain.system_call_filter().enabled(True)
    _domain.intercept_system_calls(True)
    _domain.intercept_cr_writes(3, True)

    monitor = CallMonitor(
        _domain, args.procname, module_bases, args.symbols, return_bp=not args.no_return
    )
    monitor.set_symbols_by_module(symbols_by_module)

    signal.pthread_sigmask(signal.SIG_BLOCK, [signal.SIGINT])
    listener = threading.Thread(target=_interrupt_listener, daemon=True)
    listener.start()
    _domain.poll(monitor)
    return 0


if __name__ == "__main__":
    sys.exit(main())
