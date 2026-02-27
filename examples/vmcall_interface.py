#!/usr/bin/env python3
"""IntroVirt Python example: VMCALL interface (vmcall_interface clone).

Demonstrates: (1) CSTRING_REVERSE - read C string from guest (RDX), reverse in place;
(2) WRITE_PROTECT - watchpoint on (RDX, R8), inject GP on write;
(3) PROTECT_PROCESS - block NtTerminateProcess/NtOpenProcess for protected PIDs.

Usage:
  python3 vmcall_interface.py DOMAIN

Requires root and IntroVirt-patched hypervisor. Guest must issue VMCALL with
service code in RCX (0xF000, 0xF001, 0xF002).
"""
import argparse
import signal
import sys
import threading

import introvirt

# Service codes (match C++ example)
CSTRING_REVERSE = 0xF000
WRITE_PROTECT = 0xF001
PROTECT_PROCESS = 0xF002

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


class WatchpointHandler(introvirt.WatchpointCallback):
    def __init__(self, domain):
        super().__init__()
        self._domain = domain

    def watchpoint_hit(self, event):
        """Called from C++ when watchpoint fires; must not raise or SWIG raises DirectorMethodException."""
        try:
            task = event.task()
            vcpu = event.vcpu()
            print(f"Memory access violation in {task.process_name()} [{task.pid()}:{task.tid()}]")
            if event.mem_access().write_violation():
                print(f"\tProcess wrote to read-only memory!")
                print(f"\tPhysical address: 0x{event.mem_access().physical_address_value():x}")
                print(f"\tRIP: 0x{vcpu.registers().rip():x}")
                vcpu.inject_exception(introvirt.Exception_GP_FAULT, 0)
            sys.stdout.flush()
        except Exception as e:
            import traceback
            print(f"watchpoint_hit error: {e}", file=sys.stderr)
            traceback.print_exc(file=sys.stderr)
            sys.stderr.flush()


class VmcallHandler(introvirt.EventCallback):
    def __init__(self, domain):
        super().__init__()
        self._domain = domain
        self._protected_pids = set()
        self._watchpoints = {}  # pid -> list of Watchpoint
        self._pending_terminate = {}  # (pid, tid) -> target_pid
        self._lock = threading.Lock()
        self._wp_callback = WatchpointHandler(domain)

    def process_event(self, event):
        try:
            if event.type() == introvirt.EventType_EVENT_HYPERCALL:
                self._handle_hypercall(event)
            elif event.type() == introvirt.EventType_EVENT_FAST_SYSCALL:
                self._handle_syscall(event)
            elif event.type() == introvirt.EventType_EVENT_FAST_SYSCALL_RET:
                self._handle_sysret(event)
            elif event.type() == introvirt.EventType_EVENT_MEM_ACCESS:
                self._handle_mem_access(event)
        except Exception as e:
            print(f"process_event error: {e}", file=sys.stderr)
            import traceback
            traceback.print_exc(file=sys.stderr)

    def _handle_hypercall(self, event):
        task = event.task()
        vcpu = event.vcpu()
        regs = vcpu.registers()
        print(f"{task.process_name()} [{task.pid()}:{task.tid()}]")
        print(f"\tRIP: 0x{regs.rip():x} RCX: 0x{regs.rcx():x} RDX: 0x{regs.rdx():x} R8: 0x{regs.r8():x}")
        return_code = 1
        try:
            if regs.rcx() == CSTRING_REVERSE:
                print("\tCSTRING_REVERSE requested")
                return_code = self._service_string_reverse(event)
            elif regs.rcx() == WRITE_PROTECT:
                print("\tWRITE_PROTECT requested")
                return_code = self._service_write_protect(event)
            elif regs.rcx() == PROTECT_PROCESS:
                print("\tPROTECT_PROCESS requested")
                return_code = self._service_protect_process(event)
            else:
                print(f"\tUnknown service code: 0x{regs.rcx():x}")
        except Exception as e:
            print(f"\tService error: {e}", file=sys.stderr)
            return_code = -1
        # Use helper to set RAX (overloaded regs.rax(val) has dispatch issues from Python)
        rax_val = return_code if return_code >= 0 else (1 << 64) + return_code
        introvirt.set_register_rax(regs, rax_val)
        print(f"\tReturning status code: {return_code}")
        sys.stdout.flush()

    def _service_string_reverse(self, event) -> int:
        vcpu = event.vcpu()
        regs = vcpu.registers()
        addr = regs.rdx()
        try:
            s = introvirt.read_guest_cstring(self._domain, vcpu, addr)
            print(f"\tReversing input string [{s}]")
            rev = s[::-1]
            data = rev.encode("utf-8") + b"\x00"
            introvirt.write_guest_bytes(self._domain, vcpu, addr, data)
            print(f"\tReversed string is now [{rev}]")
            return 0
        except Exception as e:
            print(f"\tString reverse failed: {e}", file=sys.stderr)
            return -1

    def _service_write_protect(self, event) -> int:
        vcpu = event.vcpu()
        regs = vcpu.registers()
        addr = regs.rdx()
        length = regs.r8()
        if length == 0:
            return -1
        try:
            wp = introvirt.create_watchpoint(
                self._domain, vcpu, addr, length,
                read=False, write=True, execute=False,
                callback=self._wp_callback,
            )
            if wp is not None:
                pid = event.task().pid()
                with self._lock:
                    self._watchpoints.setdefault(pid, []).append(wp)
                print("\tWatchpoint created successfully")
                return 0
        except Exception as e:
            print(f"\tWatchpoint failed: {e}", file=sys.stderr)
        return -1

    def _service_protect_process(self, event) -> int:
        pid = event.task().pid()
        with self._lock:
            self._protected_pids.add(pid)
        print(f"\tProtected PID {pid} from termination, injection, and debugging")
        return 0

    def _handle_syscall(self, event):
        wevent = introvirt.WindowsEvent_from_event(event)
        if wevent is None:
            return
        index = wevent.syscall().index()
        handler = wevent.syscall().handler()
        if handler is None:
            return
        task = wevent.task()
        pid = task.pid()
        tid = task.tid()

        if index == introvirt.SystemCallIndex_NtTerminateProcess and isinstance(handler, introvirt.NtTerminateProcess):
            target = handler.target_pid()
            with self._lock:
                if target in self._protected_pids:
                    handler.ProcessHandle(0xFFFFFFFFFFFFFFFF)
                    print(f"Blocked termination of protected PID {target} by {task.process_name()}[{pid}:{tid}]")
                    return
                if target == pid:
                    self._protected_pids.discard(pid)
                    self._watchpoints.pop(pid, None)
                    return
                if not handler.will_return():
                    return
            wevent.syscall().hook_return(True)
            with self._lock:
                self._pending_terminate[(pid, tid)] = target
            return

        if index == introvirt.SystemCallIndex_NtOpenProcess and isinstance(handler, introvirt.NtOpenProcess):
            target = introvirt.get_nt_open_process_target_pid(handler)
            with self._lock:
                if target in self._protected_pids:
                    introvirt.block_open_process_client_id(handler)
                    print(f"Blocked NtOpenProcess for protected PID {target} by {task.process_name()}[{pid}:{tid}]")
            return

    def _handle_sysret(self, event):
        wevent = introvirt.WindowsEvent_from_event(event)
        if wevent is None:
            return
        if wevent.syscall().index() != introvirt.SystemCallIndex_NtTerminateProcess:
            return
        handler = wevent.syscall().handler()
        if handler is None or not handler.result().NT_SUCCESS():
            return
        task = event.task()
        pid, tid = task.pid(), task.tid()
        with self._lock:
            target = self._pending_terminate.pop((pid, tid), None)
        if target is None:
            return
        with self._lock:
            if target in self._protected_pids:
                self._protected_pids.discard(target)
            self._watchpoints.pop(target, None)
        print(f"{task.process_name()} [{pid}:{tid}]")
        print(f"\tTerminated PID {target} - protections removed")
        sys.stdout.flush()

    def _handle_mem_access(self, event):
        if event.mem_access().write_violation():
            self._wp_callback.watchpoint_hit(event)


def main():
    global _domain
    parser = argparse.ArgumentParser(
        description="VMCALL interface example: string reverse, write-protect, process protection."
    )
    parser.add_argument("domain", metavar="DOMAIN", help="Domain name or ID")
    args = parser.parse_args()

    try:
        hypervisor = introvirt.Hypervisor.instance()
    except Exception as e:
        print(f"Failed to get hypervisor: {e}", file=sys.stderr)
        return 1
    try:
        _domain = hypervisor.attach_domain(args.domain)
    except Exception as e:
        print(f"Failed to attach: {e}", file=sys.stderr)
        return 1
    if not _domain.detect_guest():
        print("Failed to detect guest OS", file=sys.stderr)
        return 1

    guest = _domain.guest()
    if guest is None or guest.os() != introvirt.OS_Windows:
        print("Windows guest required", file=sys.stderr)
        return 1
    win_guest = introvirt.WindowsGuest_from_guest(guest)
    if win_guest is None:
        print("Windows guest required", file=sys.stderr)
        return 1

    # Match vmcall_interface.cc: set trap at guest level only, then enable at domain level (no set_64).
    win_guest.set_system_call_filter(
        _domain.system_call_filter(), introvirt.SystemCallIndex_NtTerminateProcess, True
    )
    win_guest.set_system_call_filter(
        _domain.system_call_filter(), introvirt.SystemCallIndex_NtOpenProcess, True
    )
    _domain.system_call_filter().enabled(True)
    _domain.intercept_system_calls(True)

    handler = VmcallHandler(_domain)
    signal.pthread_sigmask(signal.SIG_BLOCK, [signal.SIGINT])
    listener = threading.Thread(target=_interrupt_listener, daemon=True)
    listener.start()
    _domain.poll(handler)
    return 0


if __name__ == "__main__":
    sys.exit(main())
