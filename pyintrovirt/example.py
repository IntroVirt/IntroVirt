#!/usr/bin/env python3
"""@example example.py

IntroVirt Python example: A simple example.

Demonstrates the minimal Python API: attach to a domain, list running domains, and print the version of the hypervisor.

Usage:
  python3 example.py --list
  python3 example.py --version
  python3 example.py --domain win10 --syscall ntcreatefile --syscall ZwClose --syscall NTREADFILE --syscall 50
"""
import argparse
import traceback
from pyintrovirt import VMI

import introvirt


def print_version(vmi: VMI):
    """Print the version of the hypervisor"""
    print(f"Hypervisor: {vmi.hypervisor_name()}")
    print(f"Version: {vmi.hypervisor_version()}")
    print(f"Patch: {vmi.hypervisor_patch_version()}")
    print(f"Library: {vmi.library_name()} {vmi.library_version()}")


def list_domains(vmi: VMI):
    """List all running domains"""
    domains = vmi.get_running_domains()
    print("Running domains:")
    for domain in domains:
        print(f"  - {domain.domain_name} (ID: {domain.domain_id})")


def handle_syscall(event: introvirt.Event):
    """Handle a system call"""
    vcpu = event.vcpu()
    task = event.task()
    syscall = event.syscall()
    print(f"Vcpu {vcpu.id()}: [{task.pid()}:{task.tid()}] {task.process_name()}\n"
          f"\t{syscall.name()}\n")


def main():
    """Entry Point."""
    parser = argparse.ArgumentParser("ivexample", description="A simple example.")
    parser.add_argument("-d", "--domain", help="Attach to the target domain by name or PID")
    parser.add_argument("-l", "--list", action="store_true", help="List all running domains")
    parser.add_argument("-v", "--version", action="store_true", help="Show the version of the hypervisor")
    parser.add_argument("-s", "--syscall", action="append", help="Filter for the specified system call")
    args = parser.parse_args()

    if not args.domain and not args.list and not args.version:
        parser.error("Either --target, --list, or --version must be specified")

    try:
        with VMI(args.domain) as vmi:
            if args.version:
                print_version(vmi)
                return
            elif args.list:
                list_domains(vmi)
                return

            print(f"Guest: {vmi.guest_os().name}")
            vmi.register_callback(introvirt.EventType.EVENT_FAST_SYSCALL, handle_syscall)

            if args.syscall:
                vmi.filter_system_calls(args.syscall)

            vmi.intercept_system_calls(True)
            vmi.poll(blocking=True)  # Handles cntrl+c for you

    except Exception as exc:
        traceback.print_exc()


if __name__ == "__main__":
    main()