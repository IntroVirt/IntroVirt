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
 * @example ivbugcheck.cc
 *
 * Reads the kernel's KiBugCheckData array from a (typically bugchecked) Windows
 * guest and decodes the stop code + 4 parameters. For IRQL_NOT_LESS_OR_EQUAL
 * (0x0A) it interprets the params and resolves the faulting address and
 * referenced address to loaded kernel modules.
 */

#include <introvirt/introvirt.hh>

#include <boost/program_options.hpp>

#include <iomanip>
#include <iostream>
#include <string>

using namespace introvirt;
using namespace introvirt::windows;
using namespace introvirt::windows::nt;

namespace po = boost::program_options;

static std::string resolve_module(const WindowsGuest& guest, uint64_t addr) {
    if (!addr)
        return "(null)";
    try {
        for (const auto& mod : guest.kernel().PsLoadedModuleList()) {
            const uint64_t base = mod->DllBase();
            const uint64_t end = base + mod->SizeOfImage();
            if (addr >= base && addr < end) {
                std::ostringstream os;
                os << mod->BaseDllName() << "+0x" << std::hex << (addr - base);
                return os.str();
            }
        }
    } catch (...) {
    }
    return "(not in a loaded module)";
}

int main(int argc, char** argv) {
    std::string domain_name;

    po::options_description desc("Options");
    // clang-format off
    desc.add_options()
      ("domain,D", po::value<std::string>(&domain_name)->required(), "The domain to attach to")
      ("help", "Display program help");
    // clang-format on

    po::variables_map vm;
    try {
        po::store(po::parse_command_line(argc, argv, desc), vm);
        if (vm.count("help")) {
            std::cout << desc << '\n';
            return 0;
        }
        po::notify(vm);
    } catch (po::error& e) {
        std::cerr << "ERROR: " << e.what() << "\n\n" << desc << std::endl;
        return 1;
    }

    auto hypervisor = Hypervisor::instance();
    auto domain = hypervisor->attach_domain(domain_name);

    if (!domain->detect_guest()) {
        std::cerr << "Failed to detect guest operating system\n";
        return 1;
    }

    domain->pause();

    auto* guest_base = domain->guest();
    if (guest_base->os() != OS::Windows) {
        std::cerr << "Not a Windows guest\n";
        domain->resume();
        return 1;
    }
    auto& guest = static_cast<WindowsGuest&>(*guest_base);

    int rc = 0;
    try {
        const auto& kernel = guest.kernel();
        const guest_ptr<void> sym = kernel.symbol("KiBugCheckData");
        const uint64_t addr = sym.address();

        // Rebind the void symbol pointer to a uint64_t[5] (the KiBugCheckData array).
        guest_ptr<uint64_t[]> data(sym, 5);
        const uint64_t code = data[0];
        const uint64_t p1 = data[1];
        const uint64_t p2 = data[2];
        const uint64_t p3 = data[3];
        const uint64_t p4 = data[4];

        std::cout << std::hex << std::showbase;
        std::cout << "KiBugCheckData @ " << addr << "\n";
        std::cout << "  BugCheckCode = " << code << "\n";
        std::cout << "  Param1       = " << p1 << "\n";
        std::cout << "  Param2       = " << p2 << "\n";
        std::cout << "  Param3       = " << p3 << "\n";
        std::cout << "  Param4       = " << p4 << "\n";

        if (code == 0) {
            std::cout << "\n(no bugcheck recorded; guest has not crashed)\n";
        } else if (code == 0x0A) {
            std::cout << "\nIRQL_NOT_LESS_OR_EQUAL (0x0A):\n";
            std::cout << "  Referenced address = " << p1 << "  -> "
                      << resolve_module(guest, p1) << "\n";
            std::cout << "  IRQL               = " << p2 << "\n";
            std::cout << "  Access             = " << (p3 ? "write" : "read") << " ("
                      << p3 << ")\n";
            std::cout << "  Faulting RIP       = " << p4 << "  -> "
                      << resolve_module(guest, p4) << "\n";
        } else {
            std::cout << "\nFaulting RIP guess (Param4) -> " << resolve_module(guest, p4) << "\n";
        }
        std::cout << std::dec << std::noshowbase;
    } catch (std::exception& ex) {
        std::cerr << "Failed to read KiBugCheckData: " << ex.what() << "\n";
        rc = 1;
    }

    domain->resume();
    return rc;
}
