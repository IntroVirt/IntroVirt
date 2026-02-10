libintrovirt {#mainpage}
============

# Introduction

This library is the core userland component of IntroVirt. It provides low-level
access to the hypervisor for introspection of guest VMs.

# Main concepts

- \ref introvirt::Hypervisor "Hypervisor" – Attach to a hypervisor and list or attach to domains.
- \ref introvirt::Domain "Domain" – Represents a single VM; create breakpoints, watchpoints, single-step, and inject calls.
- \ref introvirt::Vcpu "Vcpu" – A virtual CPU; access registers and control execution.
- \ref introvirt::Guest "Guest" – The OS running in the domain (e.g. Windows); used for OS-specific helpers and injection.
- \ref introvirt::Event "Event" – Callbacks for breakpoints, watchpoints, system calls, and other events.

See also the \ref examples_doc "Example documentation" for walkthroughs and sample code. Example source files are listed in the **Examples** menu.

# Building the docs

From the project root:

    cd build
    cmake -G Ninja -DCMAKE_BUILD_TYPE=Release -DDOXYGEN=ON ..
    ninja doc

Output is in `build/html/`. API docs are also published to GitHub Pages on push to `main`.
