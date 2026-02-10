libintrovirt {#mainpage}
============

# Introduction

**libintrovirt** is the core userland library of IntroVirt. It gives you programmatic access to a running virtual machine from the host: read and write guest memory, intercept system calls and hypercalls, set breakpoints and watchpoints, and inject code or system calls into the guest. IntroVirt works with a patched KVM hypervisor (see [kvm-introvirt](https://github.com/IntroVirt/kvm-introvirt)) and supports Windows guests with full NT system call and API coverage.

Typical use cases include monitoring or blocking guest behavior, building security and forensics tools, debugging, and implementing custom hypercall interfaces between guest and host.

# Prerequisites

- A VM running on a host with the IntroVirt KVM patch (kvm-introvirt) loaded
- libintrovirt and its dependencies built and installed (see the project README)
- For Windows guests: libmspdb for kernel structure support

# Quick start: system call monitor

The following minimal example attaches to a domain (VM), detects a Windows guest, enables system call interception, and prints each syscall as it returns. It shows the core flow: attach → detect guest → configure filter → poll with an \ref introvirt::EventCallback "EventCallback".

```cpp
#include <introvirt/introvirt.hh>
#include <csignal>
#include <iostream>

using namespace introvirt;
using namespace introvirt::windows;

static std::unique_ptr<Domain> domain;

void sig_handler(int) { domain->interrupt(); }

class MinimalSyscallMonitor : public EventCallback {
public:
    void process_event(Event& event) override {
        if (event.type() == EventType::EVENT_FAST_SYSCALL) {
            event.syscall().hook_return(true);
            return;
        }
        if (event.type() == EventType::EVENT_FAST_SYSCALL_RET) {
            auto& task = event.task();
            std::cout << "[" << task.pid() << ":" << task.tid() << "] "
                      << task.process_name() << " " << event.syscall().name() << "\n";
        }
    }
};

int main(int argc, char** argv) {
    if (argc < 2) {
        std::cerr << "Usage: " << argv[0] << " <domain>\n";
        return 1;
    }
    signal(SIGINT, sig_handler);
    auto hypervisor = Hypervisor::instance();
    domain = hypervisor->attach_domain(argv[1]);
    if (!domain->detect_guest()) {
        std::cerr << "Failed to detect guest\n";
        return 1;
    }
    if (domain->guest()->os() != OS::Windows) {
        std::cerr << "This example requires a Windows guest\n";
        return 1;
    }
    auto* guest = static_cast<WindowsGuest*>(domain->guest());
    guest->default_syscall_filter(domain->system_call_filter());
    domain->system_call_filter().enabled(true);
    domain->intercept_system_calls(true);
    MinimalSyscallMonitor mon;
    domain->poll(mon);
    return 0;
}
```

Build and run (replace `win10` with your domain name or ID):

    g++ main.cc -o basic_syscallmon -lintrovirt
    sudo ./basic_syscallmon win10

Use Ctrl+C to detach cleanly. For a full-featured syscall monitor with filtering and JSON output, see the \ref ivsyscallmon.cc "ivsyscallmon" tool.

# Main concepts

- \ref introvirt::Hypervisor "Hypervisor" – Get a hypervisor instance and attach to domains (VMs) by name or PID.
- \ref introvirt::Domain "Domain" – Represents one VM: create breakpoints and watchpoints, single-step, inject calls, and poll for events.
- \ref introvirt::Vcpu "Vcpu" – A virtual CPU: read or modify registers and control execution (e.g. inject exceptions).
- \ref introvirt::Guest "Guest" – The OS running in the domain (e.g. Windows): guest detection, memory allocation, and OS-specific helpers.
- \ref introvirt::Event "Event" – Delivered to your \ref introvirt::EventCallback "EventCallback": system calls, hypercalls, breakpoints, watchpoints, and more.

Events are handled in a single callback; you switch on `event.type()` and cast to \ref introvirt::windows::WindowsEvent "WindowsEvent" when you need Windows-specific data (e.g. syscall handler, task info).

# Example programs and tools

- **Example documentation** (\ref examples_doc) – Walkthroughs and detailed docs (e.g. vmcall_interface: hypercalls, guest/host setup, build, usage).
- **Examples menu** – List of example source files (vmcall_interface, tools) with \ref vmcall_interface.cc and others.
- **IntroVirt tools** – Ready-made utilities (ivsyscallmon, ivprocinfo, ivmemwatch, ivreadfile, etc.) in the **Examples** list; use them as reference or as-is.

# Building the documentation

From the project root:

    mkdir -p build && cd build
    cmake -G Ninja -DCMAKE_BUILD_TYPE=Release -DDOXYGEN=ON ..
    ninja doc

Output is in `build/html/`. The API docs are also published to GitHub Pages on push to `main`.
