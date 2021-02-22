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
#include <introvirt/introvirt.hh>

#include <boost/algorithm/string.hpp>
#include <boost/program_options.hpp>

#include <csignal>
#include <functional>
#include <iostream>
#include <mutex>
#include <string>

using namespace introvirt;
using namespace introvirt::windows;

namespace po = boost::program_options;

using std::placeholders::_1;

void parse_program_options(int argc, char** argv, po::options_description& desc,
                           po::variables_map& vm);

bool interrupted = false;
std::unique_ptr<Domain> domain;

void sig_handler(int signum) {
    interrupted = true;
    domain->interrupt();
}

class EventHandler : public EventCallback {
  public:
    void process_event(Event& event) override {
        std::cout << "Received event " << event.type() << std::endl;
    }
};

void mem_callback(Event& event) {
    const Vcpu& vcpu = event.vcpu();
    const auto& regs = vcpu.registers();

    std::cout << "Vcpu " << vcpu.id() << ": [" << event.task().pid() << ":" << event.task().tid()
              << "] " << event.task().process_name() << '\n';
    std::cout << '\t' << "RIP 0x" << std::hex << regs.rip() << std::dec << '\n';

    std::cout << '\t';
    if (event.mem_access().read_violation())
        std::cout << "R";
    if (event.mem_access().write_violation())
        std::cout << "w";
    if (event.mem_access().execute_violation())
        std::cout << "X";
    std::cout << '\n';

    std::cout.flush();
}

int main(int argc, char** argv) {
    po::options_description desc("Options");

    std::string domain_name;
    std::string process_name;
    std::string address_str; // String so we can handle hex. Is there a better way?
    uint32_t length = 0;
    uint64_t pid = 0;

    // clang-format off
    desc.add_options()
      ("domain,D", po::value<std::string>(&domain_name)->required(), "The domain name or ID attach to")
      ("physical,P", "Use a physical address instead of a virtual address")
      ("procname", po::value<std::string>(&process_name), "A process name to watch")
      ("pid", po::value<uint64_t>(&pid), "A process identifier to watch")
      ("address,a", po::value<std::string>(&address_str)->required(), "An address of a buffer to watch. Requires procname or pid if not physical.")
      ("length,l", po::value<uint32_t>(&length)->default_value(1), "The length of the buffer to watch")
      ("read,r",  "Watch read accesses")
      ("write,w",  "Watch writes accesses")
      ("execute,x", "Watch instruction fetch accesses")
      ("help", "Display program help");
    // clang-format on

    // We're not mixing with printf, improve cout performance.
    std::cout.sync_with_stdio(false);

    po::variables_map vm;
    parse_program_options(argc, argv, desc, vm);

    const bool read = vm.count("read");
    const bool write = vm.count("write");
    const bool exec = vm.count("execute");
    const bool physical = vm.count("physical");

    //
    // Argument Validation
    //
    char* endptr = nullptr;
    uint64_t address = strtoull(address_str.c_str(), &endptr, 0);
    if (*endptr != '\0') {
        std::cerr << "Invalid input address: " << address_str << '\n';
        return 1;
    }

    if (!physical) {
        // Make sure a process name or PID was provided
        if (process_name.empty() && vm.count("pid") == 0) {
            std::cerr << "Virtual addresses require a process name or PID\n";
            return 1;
        }
    }

    if (!length) {
        std::cerr << "A minimum length of 1 is required\n";
        return 1;
    }

    if (!read && !write && !exec) {
        std::cerr << "At least one of read, write, or execute must be specified\n";
        return 1;
    }

    if (vm.count("pid") && !process_name.empty()) {
        std::cerr << "Specifiy either pid or procname, not both.\n";
        return 1;
    }

    // Make sure the process name (if any) is lowercase
    boost::to_lower(process_name);

    // Get a hypervisor instance
    // This will automatically select the correct type of hypervisor.
    auto hypervisor = Hypervisor::instance();

    // Attach to the domain
    signal(SIGINT, &sig_handler);
    domain = hypervisor->attach_domain(domain_name);

    // Create our watchpoint
    std::unique_ptr<Watchpoint> watchpoint;

    // Detect the guest OS
    if (!domain->detect_guest()) {
        std::cerr << "Failed to detect guest OS\n";
        return 1;
    }

    if (!physical) {
        domain->pause();

        switch (domain->guest()->os()) {
        case OS::Windows: {
            // Find a matching process
            const auto* guest = static_cast<const WindowsGuest*>(domain->guest());
            const auto& kernel = guest->kernel();
            auto cidtable = kernel.CidTable();
            std::shared_ptr<nt::PROCESS> process;

            for (const auto& entry : cidtable->open_handles()) {
                auto object_header = entry->ObjectHeader();
                if (object_header->type() == nt::ObjectType::Process) {
                    auto test_process = kernel.process(object_header->Body());
                    if (vm.count("pid") == 0) {
                        // String match
                        auto name = boost::to_lower_copy(test_process->ImageFileName());
                        if (boost::starts_with(name, process_name)) {
                            process = std::move(test_process);
                            break;
                        }
                    } else {
                        // Pid match
                        if (pid == test_process->UniqueProcessId()) {
                            process = std::move(test_process);
                            break;
                        }
                    }
                }
            }

            if (!process) {
                std::cerr << "Failed to find a matching process\n";
                return 1;
            }

            // Make the GuestVirtualAddress in the right address space
            GuestVirtualAddress gva(*domain, address, process->DirectoryTableBase());

            // Create the watchpoint
            watchpoint = domain->create_watchpoint(gva, length, read, write, exec,
                                                   std::bind(&mem_callback, _1));

            break;
        }
        default:
            std::cerr << "Unsupported OS\n";
            return 1;
        }

        domain->resume();
    } else {
        // Just get the physical address
        GuestPhysicalAddress physical_address(*domain, address);
        watchpoint = domain->create_watchpoint(physical_address, length, read, write, exec,
                                               std::bind(&mem_callback, _1));
    }

    std::cout << "Running!" << std::endl;

    // Start the poll
    EventHandler handler;
    domain->poll(handler);

    return 0;
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
            std::cout << "ivmemwatch - Watch guest memory accesses" << '\n';
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