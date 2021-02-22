/*
 * Copyright 2021 Assured Information Security, Inc.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *         http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */
/**
 * @example syscall_monitor.cc
 *
 * Basic vmcall guest communication example
 */
#include <boost/program_options.hpp>
#include <introvirt/introvirt.hh>

#include <algorithm>
#include <csignal>
#include <functional>
#include <iostream>

using namespace introvirt;
using namespace introvirt::windows;

namespace po = boost::program_options;

std::unique_ptr<Domain> domain;

// A signal handler to let the tool exit cleanly on ctrl+c
void sig_handler(int signum) { domain->interrupt(); }

// Our service codes
enum IVServiceCode { CSTRING_REVERSE = 0xF000, WRITE_PROTECT = 0xF001 };

/*
 *  This is our callback class for handling IntroVirt events
 */
class EventHandler : public EventCallback {
  public:
    /*
     * The main event callback method
     */
    void process_event(Event& event) override {
        switch (event.type()) {
        case EventType::EVENT_HYPERCALL:
            handle_hypercall(event);
            break;
        case EventType::EVENT_FAST_SYSCALL:
            handle_syscall(event);
            break;
        case EventType::EVENT_FAST_SYSCALL_RET:
            handle_sysret(event);
            break;
        default:
            // We don't care about other events
            break;
        }
    }

    void handle_syscall(Event& event) {
        auto& wevent = static_cast<WindowsEvent&>(event);
        if (wevent.syscall().index() == SystemCallIndex::NtTerminateProcess) {
            auto* handler = static_cast<nt::NtTerminateProcess*>(wevent.syscall().handler());
            if (!handler->will_return()) {
                // This call will not return, because the process is terminating itself
                std::lock_guard lock(mtx_);
                if (read_only_protections_.erase(wevent.task().pid())) {
                    auto& task = event.task();
                    std::cout << task.process_name() << " [" << task.pid() << ":" << task.tid()
                              << "]\n";
                    std::cout << '\t' << "Self terminated\n";
                }
                return;
            }

            // The call will return, so wait for that to happen
            wevent.syscall().hook_return(true);

            // Get the target PID and store it with the call
            // We have to do this because the terminated process will be unavailable upon return
            handler->data("target_pid", std::make_shared<uint64_t>(handler->target_pid()));
        }
    }

    void handle_sysret(Event& event) {
        auto& wevent = static_cast<WindowsEvent&>(event);
        if (wevent.syscall().index() == SystemCallIndex::NtTerminateProcess) {
            auto* handler = static_cast<nt::NtTerminateProcess*>(wevent.syscall().handler());
            if (!handler->result().NT_SUCCESS())
                return; // The call failed, ignore it

            // Get the process that was terminated
            const uint64_t target_pid =
                *(std::static_pointer_cast<uint64_t>(handler->data("target_pid")));

            // Erase it from our map if it exists
            std::lock_guard lock(mtx_);
            if (read_only_protections_.erase(target_pid)) {
                auto& task = event.task();
                std::cout << task.process_name() << " [" << task.pid() << ":" << task.tid()
                          << "]\n";
                std::cout << '\t' << "Terminated PID " << target_pid << '\n';
            }
        }
    }

    /*
     * Our hypercall handling code
     *
     * Print out some basic information about the hypercall,
     * and perform more complex actions if a valid service code is provided
     */
    void handle_hypercall(Event& event) {
        const auto& task = event.task();
        auto& vcpu = event.vcpu();
        auto& regs = vcpu.registers();

        std::cout << task.process_name() << " [" << task.pid() << ":" << task.tid() << "]\n";
        std::cout << std::hex;
        std::cout << '\t' << "RIP: 0x" << regs.rip() << '\n';
        std::cout << '\t' << "RAX: 0x" << regs.rax() << '\n';
        std::cout << '\t' << "RCX: 0x" << regs.rcx() << '\n';
        std::cout << '\t' << "RDX: 0x" << regs.rdx() << '\n';
        std::cout << '\t' << "R8: 0x" << regs.r8() << '\n';
        std::cout << '\t' << "R9: 0x" << regs.r9() << '\n';
        std::cout << std::dec;

        int return_code = 1;

        // Handle some special cases
        // RDX holds the function code
        switch (regs.rcx()) {
        case CSTRING_REVERSE: {
            return_code = service_string_reverse(event);
            break;
        case WRITE_PROTECT:
            return_code = service_write_protect(event);
            break;
        }
        }

        regs.rax(return_code);
    }

    int service_string_reverse(Event& event) {
        auto& vcpu = event.vcpu();
        auto& regs = vcpu.registers();

        // RDX holds a pointer to a string that we'll reverse in place
        // Get a GuestVirtualAddress based on this
        GuestVirtualAddress pStr(event.vcpu(), regs.rdx());

        try {
            // Try to map in the cstr
            guest_ptr<char[]> str = map_guest_cstr(pStr);

            // Reverse it in place
            std::cout << '\t' << "Reversing input string [" << str.get() << "]\n";
            std::reverse(str.begin(), str.end());
        } catch (VirtualAddressNotPresentException& ex) {
            // Invalid memory address provided
            std::cout << ex;
            return -1;
        }

        return 0;
    }

    int service_write_protect(Event& event) {
        auto& vcpu = event.vcpu();
        auto& regs = vcpu.registers();

        // RDX holds a pointer to a buffer
        GuestVirtualAddress pBuffer(event.vcpu(), regs.rdx());

        // R8 holds the length of the buffer
        const uint64_t length = regs.r8();

        try {
            auto wp = domain->create_watchpoint(
                pBuffer, length, false, true, false,
                std::bind(&EventHandler::memory_access_violation, this, std::placeholders::_1));

            std::cout << '\t' << "Write protecting buffer [" << pBuffer << " Len: " << length
                      << "]\n";
            std::cout << '\t' << "Physical Address: 0x" << std::hex << pBuffer.physical_address()
                      << std::dec << '\n';

            std::lock_guard lock(mtx_);
            read_only_protections_[event.task().pid()].push_back(std::move(wp));
        } catch (TraceableException& ex) {
            // Invalid parameters
            std::cerr << "Failed to create watchpoint: " << ex;
            return -1;
        }

        return 0;
    }

    void memory_access_violation(Event& event) {
        const auto& task = event.task();
        auto& vcpu = event.vcpu();
        auto& regs = vcpu.registers();

        if (event.mem_access().write_violation()) {
            std::cout << task.process_name() << " [" << task.pid() << ":" << task.tid() << "]\n";
            std::cout << '\t' << "Process wrote to read-only memory!\n";
            std::cout << '\t' << "Physical Address: " << event.mem_access().physical_address()
                      << '\n';
            std::cout << '\t' << "RIP: 0x" << std::hex << regs.rip() << std::dec << '\n';

            vcpu.inject_exception(x86::Exception::GP_FAULT, 0);

            // Release this PID's memory
            // std::lock_guard lock(mtx_);
            // read_only_protections_.erase(task.pid());
        }
    }

    // A list of our active watchpoints, by PID
    // When a watchpoint goes off-scope, it is removed.
    std::map<uint64_t, std::list<std::unique_ptr<Watchpoint>>> read_only_protections_;
    std::mutex mtx_;
};

void parse_program_options(int argc, char** argv, po::options_description& desc,
                           po::variables_map& vm);

int main(int argc, char** argv) {
    po::options_description desc("Options");
    std::string domain_name;

    // clang-format off
    desc.add_options()
      ("domain,D", po::value<std::string>(&domain_name)->required(), "The domain name or ID attach to")
      ("help", "Display program help");
    // clang-format on

    po::variables_map vm;
    parse_program_options(argc, argv, desc, vm);

    // Get a hypervisor instance
    // This will automatically select the correct type of hypervisor.
    auto hypervisor = Hypervisor::instance();

    // Attach to the domain
    domain = hypervisor->attach_domain(domain_name);

    // Set up a signal handler for ctrl+c
    signal(SIGINT, &sig_handler);

    // Detect the guest OS
    if (!domain->detect_guest()) {
        std::cerr << "Failed to detect guest OS\n";
        return 1;
    }

    // Configure the system call filter for calls we're interested in
    auto* guest = static_cast<WindowsGuest*>(domain->guest());
    guest->set_system_call_filter(domain->system_call_filter(), SystemCallIndex::NtTerminateProcess,
                                  true);
    domain->system_call_filter().enabled(true);

    // Start watching system calls
    domain->intercept_system_calls(true);

    // Start polling for events
    EventHandler handler;
    domain->poll(handler);
}

/**
 * Parse command line options here
 */
void parse_program_options(int argc, char** argv, po::options_description& desc,
                           po::variables_map& vm) {
    try {
        po::store(po::parse_command_line(argc, argv, desc), vm);
        /*
         * --help option
         */
        if (vm.count("help")) {
            std::cout << "vmcall_interface - Example VMCALL communication\n";
            std::cout << desc << '\n';
            exit(0);
        }

        po::notify(vm); // throws on error, so do after help in case
                        // there are any problems
    } catch (po::error& e) {
        std::cerr << "ERROR: " << e.what() << std::endl << std::endl;
        std::cerr << desc << std::endl;
        exit(1);
    }
}
