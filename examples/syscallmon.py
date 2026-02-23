#!/usr/bin/env python3
"""@example syscallmon.py

IntroVirt Python example: Monitor guest system calls.

Mirrors the C++ ivsyscallmon tool. Attaches to a domain, detects the guest
OS, and monitors system calls (and returns), printing each event as text or
JSON. Requires the IntroVirt Python bindings (built with -DINTROVIRT_PYTHON_BINDINGS=ON).

Usage:
  python3 syscallmon.py DOMAIN [--procname NAME] [--syscall NAME ...] [--no-flush] [--unsupported] [--json]

Requires root/sudo and an IntroVirt-patched hypervisor (e.g. KVM).

For full documentation, build instructions, and usage, see the
\\ref examples_doc "Example documentation" page.
"""
import argparse
import json
import signal
import sys
import threading

import introvirt


# Module-level domain reference for interrupt
_domain = None


def _interrupt_listener():
    """Run in a dedicated thread so Ctrl+C is handled while main thread is in C++ poll()."""
    signal.pthread_sigmask(signal.SIG_UNBLOCK, [signal.SIGINT])
    while True:
        try:
            signal.sigwait([signal.SIGINT])
        except (ValueError, OSError):
            break
        d = _domain
        if d is not None:
            d.interrupt()


class SystemCallMonitor(introvirt.EventCallback):
    """Event callback that prints syscall entries and returns."""

    def __init__(self, flush=True, json_output=False, unsupported=False):
        super().__init__()  # required so SWIG director wrapper is created for poll()
        self._flush = flush
        self._json_output = json_output
        self._unsupported = unsupported
        self._lock = __import__("threading").Lock()

    def process_event(self, event):
        try:
            self._process_event_impl(event)
        except Exception as e:
            import traceback
            print("process_event error:", e, file=sys.stderr)
            traceback.print_exc(file=sys.stderr)

    def _process_event_impl(self, event):
        etype = event.type()
        if etype == introvirt.EventType_EVENT_FAST_SYSCALL:
            syscall_ev = event.syscall()
            handler = syscall_ev.handler()
            if handler is None:
                return

            if not handler.supported():
                if self._unsupported:
                    syscall_ev.hook_return(True)
                return

            if handler.will_return():
                syscall_ev.hook_return(True)
            else:
                self._write_syscall(event)

        elif etype == introvirt.EventType_EVENT_FAST_SYSCALL_RET:
            self._write_syscall(event)

    def _write_syscall(self, event):
        with self._lock:
            vcpu = event.vcpu()
            task = event.task()
            syscall_ev = event.syscall()
            if self._json_output:
                obj = {
                    "event": "syscall_ret" if event.type() == introvirt.EventType_EVENT_FAST_SYSCALL_RET else "syscall",
                    "vcpu_id": vcpu.id(),
                    "pid": task.pid(),
                    "tid": task.tid(),
                    "process_name": task.process_name(),
                    "syscall_name": syscall_ev.name(),
                    "raw_index": syscall_ev.raw_index(),
                }
                handler = syscall_ev.handler()
                if handler is not None:
                    obj["handler_supported"] = handler.supported()
                    obj["handler_will_return"] = handler.will_return()
                else:
                    obj["handler_supported"] = None
                    obj["handler_will_return"] = None
                sys.stdout.write(json.dumps(obj) + "\n")
            else:
                line = (
                    f"Vcpu {vcpu.id()}: [{task.pid()}:{task.tid()}] {task.process_name()}\n"
                    f"{syscall_ev.name()}\n"
                )
                sys.stdout.write(line)
            if self._flush:
                sys.stdout.flush()


def main():
    global _domain
    parser = argparse.ArgumentParser(
        description="Watch guest system calls (Python port of ivsyscallmon)."
    )
    parser.add_argument(
        "domain",
        metavar="DOMAIN",
        help="Domain name or ID to attach to",
    )
    parser.add_argument(
        "--procname",
        metavar="NAME",
        help="Filter events to this process name (prefix match)",
    )
    parser.add_argument(
        "--no-flush",
        action="store_true",
        help="Don't flush stdout after each event",
    )
    parser.add_argument(
        "--unsupported",
        action="store_true",
        help="Show system calls that don't have handlers",
    )
    parser.add_argument(
        "--json",
        action="store_true",
        help="Output one JSON object per event (Python-built, no C++ JSON)",
    )
    parser.add_argument(
        "--syscall",
        metavar="NAME",
        action="append",
        dest="syscalls",
        default=None,
        help="Filter to this system call by name (e.g. NtCreateFile). Can be repeated. Windows only; ignored for Linux.",
    )
    args = parser.parse_args()

    try:
        hypervisor = introvirt.Hypervisor.instance()
    except Exception as e:
        print(f"Failed to get hypervisor: {e}", file=sys.stderr)
        return 1

    try:
        _domain = hypervisor.attach_domain(args.domain)
    except Exception as e:
        print(f"Failed to attach to domain '{args.domain}': {e}", file=sys.stderr)
        return 1

    if not _domain.detect_guest():
        print("Failed to detect guest OS", file=sys.stderr)
        return 1

    if args.procname:
        _domain.task_filter().add_name(args.procname)

    if not args.unsupported:
        _domain.system_call_filter().enabled(True)
        guest = _domain.guest()
        if guest is not None and guest.os() == introvirt.OS_Windows:
            win_guest = introvirt.WindowsGuest_from_guest(guest)
            if win_guest is not None:
                if args.syscalls:
                    _domain.system_call_filter().clear()
                    for name in args.syscalls:
                        idx = introvirt.system_call_from_string(name)
                        win_guest.set_system_call_filter(
                            _domain.system_call_filter(), idx, True
                        )
                else:
                    win_guest.default_syscall_filter(_domain.system_call_filter())

    _domain.intercept_system_calls(True)

    monitor = SystemCallMonitor(
        flush=not args.no_flush,
        json_output=args.json,
        unsupported=args.unsupported,
    )
    # Block SIGINT in main so a dedicated thread can sigwait() and call interrupt();
    # otherwise Ctrl+C is never seen while main is blocked in C++ poll().
    signal.pthread_sigmask(signal.SIG_BLOCK, [signal.SIGINT])
    listener = threading.Thread(target=_interrupt_listener, daemon=True)
    listener.start()
    _domain.poll(monitor)

    return 0


if __name__ == "__main__":
    sys.exit(main())
