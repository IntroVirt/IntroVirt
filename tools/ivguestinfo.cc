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

#include <iomanip>
#include <iostream>
#include <set>
#include <string>
#include <vector>

using namespace std;
using namespace introvirt;
using namespace introvirt::windows;
using namespace introvirt::windows::nt;
using namespace introvirt::windows::pe;

namespace po = boost::program_options;

void parse_program_options(int argc, char** argv, po::options_description& desc,
                           po::variables_map& vm);

void print_guest_information(const WindowsGuest& guest, po::variables_map& vm) {
    const auto& kernel = guest.kernel();
    const auto& debug_directory = kernel.pe().optional_header().debug_directory();
    const auto drivers = kernel.PsLoadedModuleList();

    const auto* cv_info = debug_directory->codeview_data();

    std::cout << "---------\n";
    std::cout << "  Kernel \n";
    std::cout << "---------\n";
    std::cout << "  Platform: " << (kernel.x64() ? "x64" : "x86") << " ";
    if (kernel.KdVersionBlock().Flags().MP())
        std::cout << "SMP ";
    if (kernel.KdDebuggerDataBlock().PaeEnabled())
        std::cout << "PAE ";
    std::cout << '\n';
    std::cout << "  InvalidPteMask: 0x" << std::hex << kernel.InvalidPteMask() << std::dec << '\n';
    std::cout << "  CPUs: " << kernel.cpu_count() << '\n';
    std::cout << "  Version: " << kernel.MajorVersion() << '.' << kernel.MinorVersion() << '\n';
    std::cout << "  Build: " << kernel.NtBuildNumber() << '\n';
    std::cout << "  Base: " << kernel.base_address() << '\n';
    if (cv_info) {
        std::cout << "  PDB: " << cv_info->PdbFileName() << " " << cv_info->PdbIdentifier() << '\n';
    }
    std::cout << "  System calls: " << guest.syscalls().count() << '\n';

    std::cout << "  Loaded kernel modules: " << drivers.size() << '\n';
    if (vm.count("drivers")) {
        for (const auto& module : kernel.PsLoadedModuleList()) {
            std::cout << "    " << module->DllBase() << ": " << module->FullDllName() << '\n';
        }
    }
}

int main(int argc, char** argv) {
    po::options_description desc("Options");

    std::string domain_name;
    std::vector<std::string> names;
    std::vector<uint64_t> pids;

    // clang-format off
    desc.add_options()
      ("domain,D", po::value<std::string>(&domain_name)->required(), "The domain name or ID attach to")
      ("drivers", "List kernel drivers")
      ("help", "Display program help");
    // clang-format on

    po::variables_map vm;
    parse_program_options(argc, argv, desc, vm);

    // Get a hypervisor instance
    // This will automatically select the correct type of hypervisor.
    auto hypervisor = Hypervisor::instance();

    // Attach to the domain
    auto domain = hypervisor->attach_domain(domain_name);

    // Try to detect the guest OS
    if (!domain->detect_guest()) {
        std::cerr << "Failed to detect guest operating system\n";
        return 1;
    }

    // Pause it
    domain->pause();

    std::cout << "---------\n";
    std::cout << "  Guest  \n";
    std::cout << "---------\n";
    std::cout << "  Domain: " << domain->name() << '\n';
    std::cout << "  ID: " << domain->id() << '\n';
    std::cout << "  VCPUs: " << domain->vcpu_count() << '\n';

    // Parse Windows information
    auto* guest = domain->guest();
    if (guest->os() == OS::Windows) {
        print_guest_information(static_cast<WindowsGuest&>(*guest), vm);
    }

    // Resume it
    domain->resume();

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
            std::cout << "ivprocinfo - Display process information" << '\n';
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