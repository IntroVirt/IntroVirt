#!/usr/bin/env python3
"""@example example.py

IntroVirt Python example: A simple example.

Demonstrates the minimal Python API: attach to a domain, list running domains, and print the version of the hypervisor.

Usage:
  python3 example.py --list
  python3 example.py --version
  python3 example.py --domain win10 --syscall NtCreateUserProcess
"""
import argparse
import traceback
from pyintrovirt import VMI, EventType, Event


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


def handle_syscall(event: Event):
    """Handle a system call"""
    if not event.will_return():
        print(event)
        return
    event.hook_return(True)


def main():
    """Entry Point."""
    parser = argparse.ArgumentParser("ivexample", description="A simple example.")
    parser.add_argument("-d", "--domain", help="Attach to the target domain by name or PID")
    parser.add_argument("-l", "--list", action="store_true", help="List all running domains")
    parser.add_argument("--list-categories", action="store_true", help="List system call categories available for the domain.")
    parser.add_argument("-v", "--version", action="store_true", help="Show the version of the hypervisor")
    parser.add_argument("-s", "--syscall", action="append", help="Filter for the specified system call", dest="syscalls")
    parser.add_argument("-c", "--category", action="append", help="Filter by system call category", dest="categories")
    parser.add_argument("--unsupported", action="store_true", help="Show unsupported system calls (no filter at all. Only works if no other filters are provided)")
    args = parser.parse_args()

    if not args.domain and not args.list and not args.version:
        parser.error("Either --target, --list, or --version must be specified")

    if args.unsupported and (args.syscalls or args.categories):
        parser.error("--unsupported won't do anything if other filters (--category, --syscall) are supplied.")

    try:
        with VMI(args.domain) as vmi:
            # Just print the version info and exit (like ivversion)
            if args.version:
                print_version(vmi)
                return

            # List available domains
            elif args.list:
                list_domains(vmi)
                return

            # Get the system call categories and print the list if requested
            print(f"Guest: {vmi.guest_os().name}")
            syscall_cats = vmi.syscall_categories()
            if args.list_categories:
                print("System call categories:")
                for cat in syscall_cats:
                    print(f"\t{cat}")
                return

            # Setup the category filters
            if args.categories:
                for cat in args.categories:
                    if cat not in syscall_cats:
                        parser.error(f"{cat} is not a valid system call category. View the list with --list-categories (domain required)")
                    else:
                        vmi.filter_system_call_category(cat)

            # Set our specific set of system calls to filter, otherwise set the default set
            # unless --unsupported is set, then don't filter anything.
            if args.syscalls:
                vmi.filter_system_calls(args.syscalls)
            elif not args.unsupported:
                vmi.default_system_call_filter()

            # Register our system call callbacks
            vmi.register_callback(EventType.EVENT_FAST_SYSCALL, handle_syscall)
            vmi.register_callback(EventType.EVENT_FAST_SYSCALL_RET, handle_syscall)
            vmi.intercept_system_calls(True)
            vmi.poll(blocking=True)  # Handles cntrl+c for you

    except Exception as exc:
        traceback.print_exc()


if __name__ == "__main__":
    main()