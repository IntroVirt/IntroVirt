#!/usr/bin/env python3
"""IntroVirt Python example: API call monitor (ivcallmon clone).

Sets breakpoints on specified module!symbol patterns. Walks the process VAD tree
to find modules and uses PDB for symbol resolution (same as C++ ivcallmon).
Optional return breakpoints use read_guest_uint64 to read the return address from RSP.

Usage:
  python3 callmon.py DOMAIN --procname NAME [SYMBOL ...]

Example:
  python3 callmon.py myvm --procname notepad.exe 'ntdll!NtCreateFile' 'ntdll!Nt*'

Default symbol set is ntdll!Nt* if none provided.

Requires root and IntroVirt-patched hypervisor.
"""
import argparse
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
                    self._return_breakpoint = introvirt.create_breakpoint_holder(
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


def _filename_ends_with_dll(filename: str, dll: str) -> bool:
    """Case-insensitive check if filename ends with dll (e.g. ntdll.dll)."""
    fn, d = filename.lower().replace("/", "\\"), dll.lower()
    if not d.endswith(".dll"):
        d = d + ".dll"
    return fn.endswith(d)


class CallMonitor(introvirt.EventCallback):
    def __init__(self, domain, procname: str, requested_symbols: dict, requested_dlls: set,
                 return_bp: bool):
        super().__init__()
        self._domain = domain
        self._procname = procname
        self._requested_symbols = requested_symbols  # module_name -> list of patterns
        self._requested_dlls = requested_dlls       # e.g. {"ntdll.dll"}
        self._return_bp = return_bp
        self._breakpoints = []  # list of (handler, bp) to keep handler alive for C++ callback
        self._found_dlls = set()
        self._all_symbols_resolved = False
        self._initial_check_done = False
        self._lock = threading.Lock()

    def process_event(self, event):
        try:
            if event.type() == introvirt.EventType_EVENT_FAST_SYSCALL:
                self._handle_syscall(event)
            elif event.type() == introvirt.EventType_EVENT_FAST_SYSCALL_RET:
                self._handle_sysret(event)
            elif event.type() == introvirt.EventType_EVENT_CR_WRITE:
                if event.cr().index() == 3:
                    if not self._initial_check_done:
                        self._initial_check_done = True
                        self._domain.intercept_cr_writes(3, False)
                        print("Initial CR3 write event, turning off CR3 monitoring")
                        self._set_breakpoints(event)
        except Exception as e:
            print(f"process_event error: {e}", file=sys.stderr)
            import traceback
            traceback.print_exc(file=sys.stderr)

    def _handle_syscall(self, event):
        wevent = introvirt.WindowsEvent_from_event(event)
        if wevent is not None and wevent.syscall().index() == introvirt.SystemCallIndex_NtMapViewOfSection:
            wevent.syscall().hook_return(True)
        if not self._initial_check_done:
            self._initial_check_done = True
            print("Initial syscall event, setting breakpoints")
            self._set_breakpoints(event)

    def _handle_sysret(self, event):
        wevent = introvirt.WindowsEvent_from_event(event)
        if wevent is None:
            return
        if wevent.syscall().index() == introvirt.SystemCallIndex_NtMapViewOfSection:
            handler = wevent.syscall().handler()
            ok, result = introvirt.get_windows_syscall_result_value(event)
            if handler is not None and ok and introvirt.nt_success(result):
                print("NtMapViewOfSection succeeded, setting breakpoints")
                self._set_breakpoints(event)
        if self._all_symbols_resolved:
            self._domain.intercept_system_calls(False)

    def _set_breakpoints(self, event):
        with self._lock:
            if self._all_symbols_resolved:
                return
            wevent = introvirt.WindowsEvent_from_event(event)
            if wevent is None:
                return
            task = event.task()
            vcpu = event.vcpu()
            pid = task.pid()
            modules = introvirt.get_executable_mapped_modules(event)
            for base, filename in modules:
                filename_lower = filename.lower().replace("/", "\\")
                matched_dll = None
                for dll in self._requested_dlls:
                    if _filename_ends_with_dll(filename, dll):
                        matched_dll = dll
                        break
                if matched_dll is None or matched_dll in self._found_dlls:
                    continue
                module_name = matched_dll[:-4] if matched_dll.lower().endswith(".dll") else matched_dll
                patterns = self._requested_symbols.get(module_name)
                if not patterns:
                    continue
                try:
                    print(f"Resolving symbols for {filename} with patterns {patterns}")
                    symbol_list = introvirt.resolve_symbols_via_pdb(
                        self._domain, vcpu, base, patterns
                    )
                    print(f"Resolved symbols: {symbol_list}")
                except Exception:
                    import traceback
                    traceback.print_exc(file=sys.stderr)
                    continue

                for addr, name in symbol_list:
                    print(f"Creating breakpoint for {module_name}!{name} at {addr}")
                    handler = BreakpointHandler(
                        self._domain, f"{module_name}!{name}", pid, self._return_bp
                    )
                    bp = introvirt.create_breakpoint_holder(self._domain, vcpu, addr, handler)
                    if bp is not None:
                        self._breakpoints.append((handler, bp))
                self._found_dlls.add(matched_dll)
                if len(self._found_dlls) >= len(self._requested_dlls):
                    self._all_symbols_resolved = True
                    self._domain.intercept_system_calls(False)
                    return


def main():
    global _domain
    parser = argparse.ArgumentParser(
        description="Monitor API calls via breakpoints (ivcallmon clone). VAD + PDB symbol resolution."
    )
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
    guest = _domain.guest()
    if guest is None or guest.os() != introvirt.OS_Windows:
        print("callmon only supports Windows guests", file=sys.stderr)
        return 1

    _domain.task_filter().add_name(args.procname)
    win_guest = introvirt.WindowsGuest_from_guest(guest)
    if win_guest is not None:
        _domain.system_call_filter().enabled(True)
        win_guest.set_system_call_filter(
            _domain.system_call_filter(),
            introvirt.SystemCallIndex_NtMapViewOfSection,
            True,
        )
    _domain.intercept_system_calls(True)
    _domain.intercept_cr_writes(3, True)

    monitor = CallMonitor(
        _domain, args.procname, requested_symbols, requested_dlls,
        return_bp=not args.no_return,
    )

    signal.pthread_sigmask(signal.SIG_BLOCK, [signal.SIGINT])
    listener = threading.Thread(target=_interrupt_listener, daemon=True)
    listener.start()
    _domain.poll(monitor)
    return 0


if __name__ == "__main__":
    sys.exit(main())
