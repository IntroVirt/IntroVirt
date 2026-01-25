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
 * @example vmcall_interface.cc
 *
 * This example demonstrates how to implement a simple VMCALL interface
 * between a guest and the hypervisor using IntroVirt. The guest can
 * make VMCALLs with specific service codes to request services from
 * the hypervisor.
 *
 * This example shows how IntroVirt can be used to add powerful protections
 * to in-guest applications with minimal code changes.
 *
 * To read this example, it's best to skip down to main() first before looking at
 * the EventHandler class.
 *
 * This example is more verbosely documented than other examples in the tools/ directory
 * as it is intended to be instructional.
 *
 * There is a companion example in the examples/guest/vmcall_interface/ directory
 * that shows how to make VMCALLs from within a Windows guest.
 */
#include <boost/program_options.hpp>
#include <introvirt/introvirt.hh>

#include <algorithm>
#include <csignal>
#include <functional>
#include <iostream>

using namespace std;
using namespace introvirt;
using namespace introvirt::windows;
namespace po = boost::program_options;

// This gives us global access to the attached domain (VM)
unique_ptr<Domain> domain;

// These are our service codes. They are arbitrary values chosen for this example.
// They define the actions that the hypervisor will take upon receiving a VMCALL.
enum IVServiceCode { CSTRING_REVERSE = 0xF000, WRITE_PROTECT = 0xF001 };

void sig_handler(int signum);
void parse_program_options(int argc, char** argv, po::options_description& desc, po::variables_map& vm);

/**
 * This is our callback class for handling IntroVirt events.
 * It implements the core logic for this example.
 *
 * It processes all received events, handling hypercalls and system calls as needed.
 * In the case of this example, we only need to track NtTerminateProcess system calls
 * so we can clean up our write-protections when a process terminates itself.
 */
class EventHandler : public EventCallback {
  public:
    /**
     * The main event callback method. Every event received from the hypervisor
     * is passed to this method for processing. We only care about hypercalls and
     * system calls in this example.
     *
     * The EVENT_FAST_SYSCALL_RET event is used to handle the return from system calls.
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
            cout << "Unhandled event type: " << event.type() << "\n";
            break;
        }
    }

    /**
     * This method is called when we receive a EVENT_FAST_SYSCALL event.
    */
    void handle_syscall(Event& event) {
        // We know it's a WindowsEvent, because we only support windows guests in this example.
        auto& wevent = static_cast<WindowsEvent&>(event);

        // This shouldn't even be necessary since we're filtering to only NtTerminateProcess, but we'll check anyway.
        if (unlikely(wevent.syscall().index() != SystemCallIndex::NtTerminateProcess)) {
            // We only care about NtTerminateProcess calls
            return;
        }

        // Now that we know it's NtTerminateProcess, we can cast the handler to the correct type
        auto* handler = static_cast<nt::NtTerminateProcess*>(wevent.syscall().handler());

        // NtTerminateProcess will not return when a process is terminating itself.
        // We need to handle this case and check if we have any write-protections to clean up.
        if (!handler->will_return()) {
            lock_guard lock(mtx_);

            // If we have any write-protections for this PID, remove them now
            if (read_only_protections_.erase(wevent.task().pid())) {
                // Just some logging after removing from the list.
                auto& task = event.task();
                cout << task.process_name() << " [" << task.pid() << ":" << task.tid()
                            << "]\n";
                cout << '\t' << "Self terminated\n";
            }
            return;  // Nothing else to do. The call won't return, so we're done.
        }

        //
        // The call will return, so we need to wait for that to happen before cleaning up.
        // We can't just remove the protections now, because the process might still need them.
        // Furthermore, the call to NtTerminateProcess might fail, in which case we don't want to
        // remove the protections at all. We can't be sure the process trying to terminate this process
        // is even allowed to do so.
        //

        // In order to handle the return, we need to set the syscall to hook its return.
        wevent.syscall().hook_return(true);

        // Unfortunately, upon return from NtTerminateProcess, the process being terminated
        // will no longer be valid and so we won't be able to get its PID then. So we need to get
        // it now.
        //
        // However, IntroVirt has a built-in mechanism for us to store arbitrary data with system call handlers.
        // We can store key-value pairs with the handler that will persist until the handler is destroyed.
        //
        // So we can put our PID in a "target_pid" key and look it up later when the call returns.
        handler->data("target_pid", make_shared<uint64_t>(handler->target_pid()));
    }

    /**
     * This method is called when we receive a EVENT_FAST_SYSCALL_RET event.
    */
    void handle_sysret(Event& event) {
        // We know it's a WindowsEvent, because we only support windows guests in this example.
        auto& wevent = static_cast<WindowsEvent&>(event);

        // This shouldn't even be necessary since we're filtering to only NtTerminateProcess, but we'll check anyway.
        if (unlikely(wevent.syscall().index() != SystemCallIndex::NtTerminateProcess)) {
            // We only care about NtTerminateProcess calls
            return;
        }

        // Now that we know it's NtTerminateProcess, we can cast the handler to the correct type
        auto* handler = static_cast<nt::NtTerminateProcess*>(wevent.syscall().handler());

        // Now, possibly unintuitively, unless you work in the Windows kernel often, we actually want to
        // check the result of the call here. If the call failed, we don't need to do anything. The
        // process isn't going to be terminated, so we can just return.
        //
        // This is a common pattern when dealing with system call returns. Always check if the call succeeded
        // before taking any action based on the assumption that it did.
        if (!handler->result().NT_SUCCESS()) {
            return;
        }

        //
        // The call succeeded, so we can now clean up our write-protections if we have any.
        //

        // Get the process that was terminated from our stored data in the handler.
        const uint64_t target_pid = *(static_pointer_cast<uint64_t>(handler->data("target_pid")));

        // Erase it from our map if it exists
        lock_guard lock(mtx_);
        if (read_only_protections_.erase(target_pid)) {
            // Just some logging after removing from the list.
            auto& task = event.task();
            cout << task.process_name() << " [" << task.pid() << ":" << task.tid()
                        << "]\n";
            cout << '\t' << "Terminated PID " << target_pid << '\n';
        }
    }

    /**
     * This method is called when we receive a EVENT_HYPERCALL event.
     *
     * Here we print out some basic information about the hypercall,
     * and perform more complex actions if a valid service code is provided in the RCX register.
     */
    void handle_hypercall(Event& event) {
        // Here we show how we can get the VCPU, process, and thread.
        const auto& task = event.task();
        auto& vcpu = event.vcpu();
        auto& regs = vcpu.registers();

        // Lets log some basic information about the hypercall.
        // This is also a useful example of how to get process and thread information
        // as well as vcpu register state.
        cout << task.process_name() << " [" << task.pid() << ":" << task.tid() << "]\n";
        cout << hex;
        cout << '\t' << "RIP: 0x" << regs.rip() << '\n';
        cout << '\t' << "RAX: 0x" << regs.rax() << '\n';
        cout << '\t' << "RCX: 0x" << regs.rcx() << '\n';
        cout << '\t' << "RDX: 0x" << regs.rdx() << '\n';
        cout << '\t' << "R8: 0x" << regs.r8() << '\n';
        cout << '\t' << "R9: 0x" << regs.r9() << '\n';
        cout << dec;

        // We'll default to an error return code and let the service handlers
        // set it to success if they complete successfully.
        int return_code = 1;

        // Handle some special cases
        // RCX holds the function code
        switch (regs.rcx()) {
        case CSTRING_REVERSE:
            // They asked to reverse a string
            return_code = service_string_reverse(event);
            break;
        case WRITE_PROTECT:
            // They asked to write-protect a memory region
            return_code = service_write_protect(event);
            break;
        default:
            // They asked for something we don't recognize
            cout << '\t' << "Unknown service code: 0x" << hex << regs.rcx() << dec
                      << '\n';
            break;
        }

        // Set the return code in RAX
        // This follows the x86-64 calling convention for integer return values.
        regs.rax(return_code);
    }

    /**
     * This is the handler for the CSTRING_REVERSE service code.
     *
     * It demonstrates how to read a C-style string from guest memory,
     * reverse it in place, and handle any potential memory access issues.
     *
     * It is very common to need to read and write guest memory when writing IntroVirt
     * tools. The guest_ptr<> class and related helper functions make this easy and safe.
     */
    int service_string_reverse(Event& event) {
        auto& vcpu = event.vcpu();
        auto& regs = vcpu.registers();

        try {
            // RDX holds a pointer to a string that we'll reverse in place
            guest_ptr<void> pStr(event.vcpu(), regs.rdx());

            // Try to map in the cstr
            guest_ptr<char[]> str = map_guest_cstring(pStr);

            // Reverse it in place
            cout << '\t' << "Reversing input string [" << str.get() << "]\n";
            reverse(str.begin(), str.end());
        } catch (VirtualAddressNotPresentException& ex) {
            // Invalid memory address provided
            cout << ex;
            return -1;
        }
        return 0;
    }

    /**
     * This is the handler for the WRITE_PROTECT service code.
     *
     * It demonstrates how to create a watchpoint on a memory region
     * to make it read-only from the guest's perspective.
     * Any write attempts to this region will trigger a memory access violation
     * that we can handle in the hypervisor.
     */
    int service_write_protect(Event& event) {
        auto& vcpu = event.vcpu();
        auto& regs = vcpu.registers();

        try {
            // RDX holds a pointer to a buffer
            guest_ptr<void> pBuffer(event.vcpu(), regs.rdx());

            // R8 holds the length of the buffer
            const uint64_t length = regs.r8();

            // Create a watchpoint on this buffer to make it read-only
            auto wp = domain->create_watchpoint(
                pBuffer, length, false, true, false,
                bind(&EventHandler::memory_access_violation, this, placeholders::_1));

            cout << '\t' << "Write protecting buffer [" << pBuffer << " Len: " << length
                      << "]\n";

            // Store this watchpoint so we can clean it up later when the process exits.
            lock_guard lock(mtx_);
            read_only_protections_[event.task().pid()].push_back(move(wp));
        } catch (TraceableException& ex) {
            // Invalid parameters
            cerr << "Failed to create watchpoint: " << ex;
            return -1;
        }

        return 0;
    }

    /**
     * This is our memory access violation handler.
     */
    void memory_access_violation(Event& event) {
        const auto& task = event.task();
        auto& vcpu = event.vcpu();
        auto& regs = vcpu.registers();

        if (event.mem_access().write_violation()) {
            cout << task.process_name() << " [" << task.pid() << ":" << task.tid() << "]\n";
            cout << '\t' << "Process wrote to read-only memory!\n";
            cout << '\t' << "Physical Address: " << event.mem_access().physical_address()
                      << '\n';
            cout << '\t' << "RIP: 0x" << hex << regs.rip() << dec << '\n';

            // Inject a general protection fault into the guest
            vcpu.inject_exception(x86::Exception::GP_FAULT, 0);
        }
    }

    // A list of our active watchpoints, by PID
    // When a watchpoint goes off-scope, it is removed.
    map<uint64_t, list<unique_ptr<Watchpoint>>> read_only_protections_;

    // Mutex to protect our map
    // IntroVirt is inherently multi-threaded. Events can be delivered
    // on different threads and VCPUs, so we need to protect our data structures.
    mutex mtx_;
};

/**
 * The main entry point for this example.
 */
int main(int argc, char** argv) {
    //
    // First we setup and parse command line options using boost::program_options.
    // This could be done in other ways as well.
    //
    string domain_name;
    po::options_description desc("Options");
    desc.add_options()
      ("domain,D", po::value<string>(&domain_name)->required(), "The domain name or ID attach to")
      ("help", "Display program help");

    po::variables_map vm;
    parse_program_options(argc, argv, desc, vm);

    //
    // Next, we get a hypervisor instance.
    // This will automatically select the correct type of hypervisor.
    //
    auto hypervisor = Hypervisor::instance();

    //
    // The domain name is passed as a required argument. This is the name of the Virtual Machine
    // to attach to. IntroVirt does nothing until it's attached to a domain.
    //
    // IntroVirt supports attaching to domains by either name or qmeu process ID.
    // The domain name is what shows in the "Name" column of "virsh list" output.
    // The domain ID is the qemu process ID as shown in "ps aux" output or "pgrep qemu".
    //
    domain = hypervisor->attach_domain(domain_name);

    //
    // Set up a signal handler for ctrl+c.
    // We need to cleanly detach from a domain before exiting. Failure to do so
    // may leave the guest in a paused state.
    //
    signal(SIGINT, &sig_handler);

    //
    // Next we detect the guest OS. This tool is designed to work with Windows guests.
    // We need to be sure we can properly detect the guest before continuing.
    //
    // This may take a few seconds and will attempt to download and parse pdb files using
    // libmspdb, if they are not already cached locally, to find important kernel structures.
    //
    if (!domain->detect_guest()) {
        cerr << "Failed to detect guest OS\n";
        return 1;
    }

    // We can check to be sure, or we could let the static_cast below throw an exception
    if (domain->guest()->os() != OS::Windows) {
        cerr << "This example only supports Windows guests\n";
        return 1;
    }

    //
    // Now we can tell IntroVirt to treat this domain as a Windows guest and configure
    // the system call filter appropriately.
    //
    // We want to filter for NtTerminateProcess because it's the only one we need.
    // This minimizes overhead.
    //
    auto* guest = static_cast<WindowsGuest*>(domain->guest());
    guest->set_system_call_filter(domain->system_call_filter(), SystemCallIndex::NtTerminateProcess, true);

    // We also need to enable the system call filter
    domain->system_call_filter().enabled(true);

    // and start watching system calls
    domain->intercept_system_calls(true);

    //
    // Finally we can create our EventHandler and start polling for events.
    // The events will be delivered to our EventHandler's process_event() method.
    //
    // Now is a good time to scroll up and read through the EventHandler class if you haven't already.
    //
    EventHandler handler;
    domain->poll(handler);
}

/**
 * This signal handler is called when the user presses ctrl+c.
 * It simply tells the domain to interrupt its polling loop so we can
 * cleanly detach and exit.
 */
void sig_handler(int signum) {
    domain->interrupt();
}

/**
 * This function parses our command line options using boost::program_options.
 * Parsing command line options is not specific to IntroVirt, so this could be
 * done in any way you like.
 */
void parse_program_options(int argc, char** argv, po::options_description& desc, po::variables_map& vm) {
    try {
        po::store(po::parse_command_line(argc, argv, desc), vm);
        /*
         * --help option
         */
        if (vm.count("help")) {
            cout << "vmcall_interface - Example VMCALL communication\n";
            cout << desc << '\n';
            exit(0);
        }

        po::notify(vm); // throws on error, so do after help in case
                        // there are any problems
    } catch (po::error& e) {
        cerr << "ERROR: " << e.what() << endl << endl;
        cerr << desc << endl;
        exit(1);
    }
}
