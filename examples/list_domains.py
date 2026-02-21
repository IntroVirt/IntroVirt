#!/usr/bin/env python3
"""@example list_domains.py

IntroVirt Python example: List running VM domains.

Demonstrates the minimal Python API: obtain a hypervisor instance, query
running domains, and print their names and IDs. Requires the IntroVirt
Python bindings (built with -DINTROVIRT_PYTHON_BINDINGS=ON).

Usage:
  python3 list_domains.py

Requires root/sudo and an IntroVirt-patched hypervisor (e.g. KVM).

For full documentation, build instructions, and usage, see the
\\ref examples_doc "Example documentation" page.
"""
import introvirt


def main():
    try:
        hv = introvirt.Hypervisor.instance()
    except Exception as e:
        print(f"Failed to get hypervisor: {e}")
        return 1

    print(f"Hypervisor: {hv.hypervisor_name()} {hv.hypervisor_version()}")
    print()

    domains = hv.get_running_domains()
    if not domains:
        print("No running domains found.")
        return 0

    print(f"Running domains ({len(domains)}):")
    for d in domains:
        print(f"  - {d.domain_name} (id={d.domain_id})")

    return 0


if __name__ == "__main__":
    exit(main())
