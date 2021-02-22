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
#include "shared/SystemCallMonitor.hh"

#include <introvirt/introvirt.hh>

#include <boost/algorithm/string.hpp>
#include <boost/program_options.hpp>

#include <csignal>
#include <iostream>
#include <mutex>
#include <string>

using namespace introvirt;
using namespace introvirt::windows;

namespace po = boost::program_options;

void parse_program_options(int argc, char** argv, po::options_description& desc,
                           po::variables_map& vm);

bool interrupted = false;
std::unique_ptr<Domain> domain;

void sig_handler(int signum) {
    interrupted = true;
    domain->interrupt();
}

int main(int argc, char** argv) {
    po::options_description desc("Options");
    std::string domain_name;
    std::string process_name;

    // clang-format off
    desc.add_options()
      ("domain,D", po::value<std::string>(&domain_name)->required(), "The domain name or ID attach to")
      ("procname", po::value<std::string>(&process_name), "A process name to filter for")
      ("no-flush", "Don't flush the output buffer after each event")
      ("json", "Output JSON format")
      ("help", "Display program help")
      ("unsupported", "Display system calls that we don't have handlers for");
    // clang-format on

    for (auto& category : WindowsGuest::syscall_categories()) {
        desc.add_options()(category.c_str(),
                           std::string("Enable " + category + " related system calls").c_str());
    }

    // We're not mixing with printf, improve cout performance.
    std::cout.sync_with_stdio(false);

    po::variables_map vm;
    parse_program_options(argc, argv, desc, vm);

    // Get a hypervisor instance
    // This will automatically select the correct type of hypervisor.
    auto hypervisor = Hypervisor::instance();

    // Attach to the domain
    signal(SIGINT, &sig_handler);
    domain = hypervisor->attach_domain(domain_name);

    // Detect the guest OS
    if (!domain->detect_guest()) {
        std::cerr << "Failed to detect guest OS\n";
        return 1;
    }

    // Configure filtering
    if (!process_name.empty()) {
        domain->task_filter().add_name(process_name);
    }

    // Turn on system call filtering unless hooking all calls
    if (vm.count("unsupported") == 0) {
        bool category_used = false;
        domain->system_call_filter().enabled(true);

        if (domain->guest()->os() == OS::Windows) {
            for (auto& category : WindowsGuest::syscall_categories()) {
                if (vm.count(category)) {
                    auto* guest = static_cast<WindowsGuest*>(domain->guest());
                    guest->enable_category(category, domain->system_call_filter());
                    category_used = true;
                }
            }
        }

        if (!category_used) {
            // Default to all supported calls
            if (domain->guest()->os() == OS::Windows) {
                auto* guest = static_cast<WindowsGuest*>(domain->guest());
                guest->default_syscall_filter(domain->system_call_filter());
            }
        }
    }

    // Enable system call hooking on all vcpus
    domain->intercept_system_calls(true);

    // Start the poll
    SystemCallMonitor monitor(!vm.count("no-flush"), vm.count("json"), vm.count("unsupported"));
    domain->poll(monitor);

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
            std::cout << "ivsyscallmon - Watch guest system calls" << '\n';
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
