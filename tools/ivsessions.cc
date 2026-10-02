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
 * @example ivsessions.cc
 *
 * Lists Windows sessions (user logon sessions) in the guest. Demonstrates
 * attaching to a domain, guest detection, and walking session structures.
 */

#include <introvirt/introvirt.hh>

#include <boost/program_options.hpp>

#include <iomanip>
#include <iostream>
#include <map>
#include <string>
#include <vector>

using namespace std;
using namespace introvirt;
using namespace introvirt::windows;
using namespace introvirt::windows::nt;

namespace po = boost::program_options;

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
    auto domain = hypervisor->attach_domain(domain_name);

    // Parse Windows information
    if (!domain->detect_guest()) {
        std::cerr << "Failed to detect guest\n";
        return 1;
    }

    auto* guest = domain->guest();
    if (guest->os() != OS::Windows) {
        std::cerr << "Only Windows guests are supported\n";
        return 1;
    }

    // Pause it
    domain->pause();

    auto* windows_guest = static_cast<WindowsGuest*>(guest);
    const NtKernel& kernel = windows_guest->kernel();

    // Get the CidTable, which holds all of the PROCESS and THREAD objects
    auto CidTable = kernel.CidTable();

    auto print_process_row = [](const PROCESS& proc) {
        cout << std::left << std::setw(5) << proc.UniqueProcessId();
        cout << std::left << std::setw(17) << proc.ImageFileName();
        cout << '\n';
    };

    // Find all of the sessions. Newer public PDBs omit _MM_SESSION_SPACE, so fall
    // back to grouping by the process token's SessionId.
    map<uint32_t, const MM_SESSION_SPACE*> sessionMap;
    std::vector<std::shared_ptr<PROCESS>> session_processes;
    bool session_type_missing = false;
    try {
        for (auto& entry : CidTable->open_handles()) {
            std::unique_ptr<OBJECT_HEADER> header(entry->ObjectHeader());
            if (header->type() == ObjectType::Process) {
                auto process = kernel.process(header->Body());
                const MM_SESSION_SPACE* session = process->Session();
                if (session) {
                    sessionMap[session->SessionID()] = session;
                    session_processes.emplace_back(std::move(process));
                }
            }
        }
    } catch (const TypeInformationException&) {
        session_type_missing = true;
        sessionMap.clear();
        session_processes.clear();
    }

    if (session_type_missing) {
        map<uint32_t, std::vector<std::shared_ptr<PROCESS>>> by_session;
        for (auto& entry : CidTable->open_handles()) {
            try {
                std::unique_ptr<OBJECT_HEADER> header(entry->ObjectHeader());
                if (header->type() != ObjectType::Process)
                    continue;
                auto process = kernel.process(header->Body());
                const uint32_t session_id = process->Token().SessionId();
                by_session[session_id].push_back(std::move(process));
            } catch (const TraceableException&) {
            }
        }

        for (const auto& entry : by_session) {
            const auto& procs = entry.second;
            cout << "*************************************************************\n";
            cout << "Session ID: " << entry.first << '\n';
            cout << procs.size() << " processes\n";
            cout << std::left << std::setw(5) << "PID";
            cout << std::left << std::setw(5) << "Name";
            cout << '\n';
            for (const auto& proc : procs)
                print_process_row(*proc);
        }
    } else {
        for (const auto& entry : sessionMap) {
            const MM_SESSION_SPACE* session = entry.second;
            const auto& sessionProcList = session->process_list();
            cout << "*************************************************************\n";
            cout << "Session " << session->ptr() << ": ";
            cout << std::right << std::setw(5);
            cout << "ID: " << session->SessionID() << '\n';

            cout << sessionProcList.size() << " processes\n";
            cout << std::left << std::setw(5) << "PID";
            cout << std::left << std::setw(5) << "Name";
            cout << '\n';

            for (auto& proc : sessionProcList)
                print_process_row(*proc);
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