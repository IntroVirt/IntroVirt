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

/*
 * Print basic process information
 */
void print_process(const PROCESS& process) {
    std::cout << "PID " << process.UniqueProcessId() << ": " << process.ImageFileName() << '\n';
    std::cout << "  EPROCESS: " << process.address() << '\n';
    std::cout << "  Parent: " << process.InheritedFromUniqueProcessId() << '\n';
    if (process.isWow64Process())
        std::cout << "  WoW64Process\n";
    std::cout << "  Session ID: ";
    if (process.Session())
        std::cout << process.Session()->SessionID() << '\n';
    else
        std::cout << "None\n";
}

/*
 * Print process token information
 */
void print_token(const PROCESS& process) {
    std::cout << "  TOKEN:\n";

    const TOKEN& token = process.Token();
    if (token.User()) {
        cout << "    User: ";
        const SID* sid = token.User();
        if (sid) {
            cout << *sid << '\n';
        } else {
            cout << "Unreadable\n";
        }
    } else {
        cout << " Unreadable\n";
    }

    if (token.PrimaryGroup()) {
        const SID* sid = token.PrimaryGroup();
        cout << "    Primary Group: ";
        if (sid) {
            cout << *sid << '\n';
        } else {
            cout << "Unreadable\n";
        }
    }

    cout << "    Groups:\n";
    size_t groupIdx = 0;
    for (const auto& sidAndAttributes : token.Groups()) {
        const auto sid = sidAndAttributes->Sid();
        cout << "      [" << groupIdx++ << "] ";
        if (sid) {
            cout << *sid << '\n';
        } else {
            cout << "Unreadable\n";
        }
        cout << "          Attributes: " << sidAndAttributes->Attributes() << '\n';
    }
}

/**
 * Retrieve PE version data for the given PE instance
 */
void getPEVersionData(const PE& pe, std::map<std::string, std::string>& result) {
    result.clear();

    const auto* resourceDir = pe.optional_header().resource_directory();

    if (resourceDir) {
        // Get the top level "version" directory (id 16)
        const auto* versionEntry = resourceDir->entry(ResourceDirType::VERSION);
        if (!versionEntry) {
            return;
        }
        const auto* versionDir = versionEntry->Directory();
        if (!versionDir) {
            return;
        }

        // Get the VERSIONINFO struct (id 1)
        const auto* versionInfoEntry = versionDir->entry(1);
        if (!versionInfoEntry) {
            return;
        }
        const auto* versionInfoDir = versionInfoEntry->Directory();
        if (!versionInfoDir) {
            return;
        }

        // Get the english version of the struct
        const auto* englishVersionInfoEntry =
            versionInfoDir->entry(LanguageId::English_United_States);
        if (!englishVersionInfoEntry) {
            return;
        }
        const auto* englishVersionInfoData = englishVersionInfoEntry->Data();
        if (!englishVersionInfoData) {
            return;
        }

        auto versionInfo = VS_VERSIONINFO::make_unique(englishVersionInfoData->data_address());
        const StringFileInfo* sfi = versionInfo->StringFileInfo();
        if (sfi) {
            const StringTable* st = sfi->StringTable();
            if (st) {
                result = st->entries();
            }
        }
    }
}

void print_peb(const PROCESS& process, bool WoW64Process) {
    if (!WoW64Process)
        std::cout << "  PEB:\n";
    else
        std::cout << "  WoW64Process PEB:\n";

    const PEB* peb;
    try {
        peb = (!WoW64Process ? process.Peb() : process.WoW64Process());
        if (!peb) {
            std::cout << "    NULL\n";
            return;
        }
    } catch (VirtualAddressNotPresentException& ex) {
        std::cout << "    Paged out\n";
        return;
    }

    cout << std::hex;
    cout << "    ImageBaseAddress: " << peb->ImageBaseAddress() << '\n';
    cout << std::dec;

    cout << "    Module List: \n";
    const PEB_LDR_DATA* ldr = peb->Ldr();
    if (!ldr) {
        std::cout << "      Unreadable\n";
        return;
    }

    const auto& moduleList = ldr->InLoadOrderList();

    for (const auto& entry : moduleList) {
        if (!entry->FullDllName().empty()) {
            cout << "      " << entry->FullDllName() << '\n';
        } else if (!entry->BaseDllName().empty()) {
            cout << "      " << entry->BaseDllName() << '\n';
        } else {
            cout << "      < Name not readable >\n";
        }
        cout << "        Base: " << entry->DllBase() << '\n';
        cout << "        Size: " << entry->SizeOfImage() << " bytes\n";
        cout << "        Entry Point: " << entry->EntryPoint() << '\n';

        try {
            auto pe = PE::make_unique(entry->DllBase());
            std::map<std::string, std::string> versionData;
            try {
                getPEVersionData(*pe, versionData);

                if (!versionData.empty()) {
                    cout << "        Version Information:\n";
                    for (auto iter : versionData) {
                        auto&& key = iter.first;
                        auto&& value = iter.second;
                        cout << "          " << key;
                        cout << ": ";
                        cout << value;
                        cout << '\n';
                    }
                }
            } catch (TraceableException& ex) {
                cout << "        Failed to get version data\n";
            }
        } catch (TraceableException& ex) {
            cout << "        Failed to parse PE Header\n";
        }
    }
}

void print_vad(const PROCESS& process) {
    cout << "  VAD:\n";

    auto vad = process.VadRoot();
    if (!vad) {
        std::cout << "    Null\n";
        return;
    }

    for (auto mmvad : vad->VadTreeInOrder()) {
        cout << "    Range: " << mmvad->StartingAddress();
        cout << " - " << mmvad->EndingAddress() << '\n';

        cout << "      Commit Charge: " << mmvad->CommitCharge() << '\n';
        cout << "      Size:   " << mmvad->RegionSize() << " bytes\n";
        cout << "      Type:   " << mmvad->Type() << '\n';
        cout << "      Allocation: " << mmvad->Allocation() << "[0x" << hex
             << mmvad->Allocation().value() << dec << "]\n";
        cout << "      Protection: " << mmvad->Protection() << "[0x" << hex
             << mmvad->Protection().value() << dec << "]\n";

        try {
            const FILE_OBJECT* fileObj = mmvad->FileObject();
            if (fileObj) {
                const DEVICE_OBJECT* dev = fileObj->DeviceObject();
                cout << "      File: ";
                if (dev) {
                    cout << dev->DeviceName();
                }
                cout << fileObj->FileName();
                cout << '\n';
            }
        } catch (TraceableException& ex) {
            cout << "      File: [Unreadable Filename]\n";
            cout << ex << '\n';
        }
    }
}

void print_environment(const PROCESS& process) {
    cout << "  Environment:\n";
    const PEB* peb;

    try {
        peb = process.Peb();
    } catch (VirtualAddressNotPresentException& ex) {
        std::cout << "    Paged out\n";
        return;
    }

    if (peb) {
        const RTL_USER_PROCESS_PARAMETERS* params = peb->ProcessParameters();
        if (params) {
            const auto& envMap = params->Environment();
            for (auto iter : envMap) {
                auto&& key = iter.first;
                auto&& value = iter.second;
                cout << "    " << key << "\n";
                cout << "      " << value << "\n";
            }
        } else {
            cout << "    RTL_USER_PROCESS_PARAMETERS Unavailable\n";
        }
    } else {
        cout << "    Null\n";
    }
}

void print_handles(const nt::NtKernel& kernel, const PROCESS& process) {
    std::cout << "  Handles:\n";
    auto table = process.ObjectTable();
    if (!table) {
        std::cout << "Null HANDLE_TABLE\n";
        return;
    }

    std::cout << "    Handle Count: " << table->HandleCount() << '\n';
    try {
        for (const auto& entry : table->open_handles()) {
            std::cout << "      0x" << std::hex << entry->Handle() << std::dec << ": ";
            try {
                auto object = OBJECT::make_shared(kernel, entry->ObjectHeader());
                std::cout << object->header().type();
                std::cout << " [" << object->address() << "]";
            } catch (TraceableException& ex) {
                std::cout << "Unable to read OBJECT_HEADER";
            }
            std::cout << '\n';
        }
    } catch (VirtualAddressNotPresentException& ex) {
        std::cout << '\n';
    }
}

void print_threads(const PROCESS& process) {
    cout << "  Threads: ";

    try {
        const auto& threadList = process.ThreadList();
        cout << "(" << threadList.size() << ")\n";

        for (const auto& thread : threadList) {
            cout << "    TID: " << thread->Cid().UniqueThread() << '\n';
            cout << hex;
            cout << "      State:             " << thread->State() << '\n';
            cout << "      CrossThreadFlags:  0x" << thread->CrossThreadFlags() << '\n';
            cout << "      Affinity:          0x" << thread->Affinity() << '\n';
            cout << "      TEB:               ";
            const TEB* teb = thread->Teb();
            if (teb) {
                cout << teb->address() << '\n';

                cout << "        LastErrorValue:  " << teb->LastErrorValue() << '\n';
                const NT_TIB& tib = teb->NtTib();
                cout << "        TIB:\n";
                cout << "          Stack Base:    " << tib.StackBase() << '\n';
                cout << "          Stack Limit:   " << tib.StackLimit() << '\n';
            } else {
                cout << "<unreadable>\n";
            }

            if (thread->State() != KTHREAD_STATE::Terminated) {
                cout << "      ETHREAD Object:    " << thread->header().Body() << '\n';
                cout << "      Win32StartAddress: " << thread->Win32StartAddress();
                // Determine which library the start address is in
                const auto pWin32StartAddress = thread->Win32StartAddress();
                auto mmvad = thread->Process().VadRoot();
                if (mmvad) {
                    auto entry = mmvad->search(pWin32StartAddress);
                    if (entry) {
                        const FILE_OBJECT* fObj = entry->FileObject();
                        if (fObj) {
                            const uint64_t offset = pWin32StartAddress - entry->StartingAddress();
                            cout << " (" << fObj->FileName() << "+0x" << offset << ")";
                        }
                    }
                }
                std::cout << '\n';
            }
            cout << std::dec;
        }
    } catch (TraceableException& ex) {
        cout << "\n   Unable to read thread list\n";
    }
}

int main(int argc, char** argv) {
    po::options_description desc("Options");

    std::string domain_name;
    std::vector<std::string> names;
    std::vector<uint64_t> pids;
    bool display_full = false;

    // clang-format off
    desc.add_options()
      ("domain,D", po::value<std::string>(&domain_name)->required(), "The domain name or ID attach to")
      ("name", po::value<std::vector<std::string>>(&names), "Only show processes beginning with the provided value. Can be called multiple times.")
      ("pid", po::value<std::vector<uint64_t>>(&pids), "Only show processes matching the given PID. Can be called multiple times.")
      ("env", "Display environmental variables")
      ("handles", "Display handle table information")
      ("peb", "Display the PEB (Process Environment Block)")
      ("thread", "Display the THREAD object in each process")
      ("token", "Display token information")
      ("vad", "Display the VAD (Virtual Address Descriptor)")
      ("full", po::bool_switch(&display_full), "Display all process information")
      ("help", "Display program help");
    // clang-format on

    po::variables_map vm;
    parse_program_options(argc, argv, desc, vm);

    // Create a set of all lowercase names
    std::set<std::string> name_filter;
    std::transform(names.begin(), names.end(), std::inserter(name_filter, name_filter.end()),
                   [](const std::string& s) -> std::string { return boost::to_lower_copy(s); });

    // Create a set of all pids
    std::set<uint64_t> pid_filter;
    std::copy(pids.begin(), pids.end(), std::inserter(pid_filter, pid_filter.end()));

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
        return 2;
    }

    const NtKernel& kernel = static_cast<WindowsGuest*>(guest)->kernel();

    // Get the CidTable, which holds all of the PROCESS and THREAD objects
    auto CidTable = kernel.CidTable();

    // Walk over the entries
    for (auto& entry : CidTable->open_handles()) {
        std::unique_ptr<OBJECT_HEADER> header(entry->ObjectHeader());
        if (header->type() == ObjectType::Process) {
            auto process = kernel.process(header->Body());

            // Check if we're filtering based on PID
            if (!pid_filter.empty() && !pid_filter.count(process->UniqueProcessId()))
                continue;

            // Check if we're filtering based on process name
            if (!name_filter.empty()) {
                const std::string ImageFileName = boost::to_lower_copy(process->ImageFileName());
                bool match = false;
                for (const std::string& name : name_filter) {
                    if (boost::starts_with(ImageFileName, name)) {
                        match = true;
                        break;
                    }
                }
                if (!match)
                    continue;
            }

            try {

                // Print the basic information
                print_process(*process);

                // Print optional information
                if (display_full || vm.count("token"))
                    print_token(*process);

                if (display_full || vm.count("peb")) {
                    print_peb(*process, false);
                    if (process->WoW64Process())
                        print_peb(*process, true);
                }

                if (display_full || vm.count("vad"))
                    print_vad(*process);

                if (display_full || vm.count("env"))
                    print_environment(*process);

                if (display_full || vm.count("handles"))
                    print_handles(kernel, *process);

                if (display_full || vm.count("thread"))
                    print_threads(*process);

            } catch (VirtualAddressNotPresentException& ex) {
                std::cout << ex;
                throw;
            }
        }
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