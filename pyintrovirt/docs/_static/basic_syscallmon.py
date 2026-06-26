# Minimal system call monitor using pyintrovirt.
# Save as basic_syscallmon.py and run: sudo python3 basic_syscallmon.py win10

import introvirt
from pyintrovirt import VMI, Event


def on_syscall(_vmi: VMI, event: Event) -> None:
    if event.event_type() == introvirt.EventType.EVENT_FAST_SYSCALL and event.will_return():
        event.hook_return(True)


def on_syscall_ret(_vmi: VMI, event: Event) -> None:
    if event.event_type() == introvirt.EventType.EVENT_FAST_SYSCALL_RET:
        print(f"[{event.pid}:{event.tid}] {event.process_name} {event.syscall_name}")


def main() -> int:
    import sys

    if len(sys.argv) < 2:
        print(f"Usage: {sys.argv[0]} <domain>")
        return 1

    with VMI(sys.argv[1]) as vmi:
        if vmi.guest_os() != introvirt.OS.Windows:
            print("This example requires a Windows guest")
            return 1
        vmi.default_system_call_filter()
        vmi.intercept_system_calls(True)
        vmi.register_callback(introvirt.EventType.EVENT_FAST_SYSCALL, on_syscall)
        vmi.register_callback(introvirt.EventType.EVENT_FAST_SYSCALL_RET, on_syscall_ret)
        vmi.poll(blocking=True)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
