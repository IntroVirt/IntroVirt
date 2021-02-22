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

int main(int argc, char** argv) {
    po::options_description desc("Options");

    std::string domain_name;
    std::vector<std::string> names;
    std::vector<uint64_t> pids;

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
    auto domain = hypervisor->attach_domain(domain_name);

    // Try to detect the guest OS
    if (!domain->detect_guest()) {
        std::cerr << "Failed to detect guest operating system\n";
        return 1;
    }

    // Pause it
    domain->pause();

    // Parse Windows information
    auto* guest = domain->guest();
    if (guest->os() != OS::Windows) {
        std::cerr << "Unsupported OS: " << guest->os() << '\n';
        domain->resume();
        return 2;
    }

    const NtKernel& kernel = static_cast<WindowsGuest*>(guest)->kernel();

    // Get the PDB so we can look up stuff
    const auto& pdb = kernel.pdb();

    // Get the service table
    const auto& service_table = kernel.KeServiceDescriptorTableShadow();

    const auto& nt_table = service_table.entry(0).service_table();
    std::cout << std::hex;
    for (unsigned int i = 0; i < nt_table.length(); ++i) {
        const auto& entry = nt_table.entry(i);
        std::cout << "0x" << std::setw(4) << std::setfill('0') << i << "  " << entry << " ";

        const uint64_t rva = entry - kernel.base_address();
        const auto* symbol = pdb.rva_to_symbol(rva);
        if (!symbol)
            continue;
        std::cout << ": " << symbol->name() << '\n';
    }

    // Win32k
    // First get the address of the win32k module
    GuestVirtualAddress pWin32k;
    for (auto& module : kernel.PsLoadedModuleList()) {
        if (module->BaseDllName() == "win32k.sys") {
            pWin32k = module->DllBase();
            break;
        }
    }

    if (unlikely(!pWin32k)) {
        std::cout << "Failed to find Win32k module\n";
        domain->resume();
        return 1;
    }

    /*
     * Find a process that has win32k mapped in
     * Not all of them do, and we're not in the right
     * address space, then the PE parsing won't work.
     */
    const auto& win32k_table = service_table.entry(1).service_table();

    bool success = false;
    auto CidTable = kernel.CidTable();
    for (auto& entry : CidTable->open_handles()) {
        std::unique_ptr<nt::OBJECT_HEADER> header(entry->ObjectHeader());
        if (header->type() == nt::ObjectType::Process) {
            auto process = kernel.process(header->Body());
            if (process->Win32Process()) {
                try {
                    pWin32k.page_directory(process->DirectoryTableBase());
                    auto win32k = pe::PE::make_unique(pWin32k);

                    std::cout << std::hex;
                    for (unsigned int i = 0; i < win32k_table.length(); ++i) {
                        const auto& entry = win32k_table.entry(i);
                        std::cout << "0x" << std::setw(4) << std::setfill('0') << (i + 0x1000)
                                  << "  " << entry << " ";

                        const uint64_t rva = entry - pWin32k;
                        const auto* symbol = win32k->pdb().rva_to_symbol(rva);
                        std::cout << ": " << symbol->name() << '\n';
                    }

                    success = true;
                    break;
                } catch (TraceableException& ex) {
                }
            }
        }
    }

    if (!success) {
        std::cout << "Failed to parse win32k service table\n";
        domain->resume();
        return 1;
    }

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