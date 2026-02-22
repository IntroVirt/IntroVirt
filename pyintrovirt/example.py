import time
import argparse
from pyintrovirt import VMI, EventType


def handle_syscall(event):
    """Handle a system call"""
    vcpu = event.vcpu()
    task = event.task()
    syscall = event.syscall()
    print(f"Vcpu {vcpu.id()}: [{task.pid()}:{task.tid()}] {task.process_name()}\n"
          f"\t{syscall.name()}\n")


def main():
    """Entry Point."""
    parser = argparse.ArgumentParser("ivexample", description="A simple example.")
    parser.add_argument("-t", "--target", help="Attach to the target VM/Domain by name or PID", required=True)
    args = parser.parse_args()

    try:
        with VMI(args.target) as vm:
            print(f"Hypervisor: {vm.hypervisor_name()}")
            print(f"Version: {vm.hypervisor_version()}")
            print(f"Patch: {vm.hypervisor_patch_version()}")
            print(f"Guest: {vm.guest_os()}")

            vm.register_callback(EventType.EVENT_FAST_SYSCALL, handle_syscall)
            vm.intercept_system_calls(True)
            vm.start_event_poller(blocking=True)
    except Exception as exc:
        print(exc)


if __name__ == "__main__":
    main()