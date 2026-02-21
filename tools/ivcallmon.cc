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
 * @example ivcallmon.cc
 *
 * Monitors Windows API function calls in a guest by setting breakpoints on
 * specified library/function names. Demonstrates breakpoint creation and
 * event handling for a target process.
 */

#include <introvirt/introvirt.hh>

#include <boost/algorithm/string.hpp>
#include <boost/program_options.hpp>
#include <log4cxx/logger.h>

#include <atomic>
#include <csignal>
#include <iostream>
#include <mutex>
#include <set>
#include <sstream>
#include <string>
#include <unordered_map>
#include <vector>

using namespace introvirt;
using namespace introvirt::windows;

namespace po = boost::program_options;

static log4cxx::LoggerPtr logger(log4cxx::Logger::getLogger("introvirt.tools.ivcallmon"));

void parse_program_options(int argc, char** argv, po::options_description& desc,
                           po::variables_map& vm);

static bool wildcard_match(const char* pp, const char* ss) {
    if (*pp == '\0')
        return *ss == '\0';
    if (*pp == '*')
        return wildcard_match(pp + 1, ss) || (*ss != '\0' && wildcard_match(pp, ss + 1));
    if (*pp == '?' && *ss != '\0')
        return wildcard_match(pp + 1, ss + 1);
    return (*pp == *ss && *ss != '\0' && wildcard_match(pp + 1, ss + 1));
}

static bool symbol_matches_pattern(const std::string& pattern, const std::string& symbol) {
    std::string p = pattern;
    std::string s = symbol;
    boost::algorithm::to_lower(p);
    boost::algorithm::to_lower(s);
    return wildcard_match(p.c_str(), s.c_str());
}

std::unique_ptr<Domain> domain;

void sig_handler(int signum) { domain->interrupt(); }

class BreakpointHandler final {
  public:
    void breakpoint_hit(Event& event) {
        if (event.task().pid() != pid_)
            return;

        std::cout << "[" << event.task().pid() << ':' << event.task().tid() << "] "
                  << event.task().process_name() << '\n';
        std::cout << "    Hit breakpoint " << name_ << '\n';

        return_tid_ = event.task().tid();
        return_rsp_ = event.vcpu().registers().rsp() + 8;

        const auto& vcpu = event.vcpu();
        const auto& regs = vcpu.registers();

        // Read the value at RSP
        guest_ptr<guest_size_t*, guest_size_t> ppreturn_address(vcpu, regs.rsp());
        auto test = ppreturn_address.get();

        // Create another pointer using the value at RSP
        guest_ptr<guest_size_t> preturn_address = ppreturn_address.get();

        return_bp_ =
            domain_->create_breakpoint(preturn_address, std::bind(&BreakpointHandler::return_hit,
                                                                  this, std::placeholders::_1));

        std::cout.flush();
    }

    void return_hit(Event& event) {
        if (event.task().tid() != return_tid_)
            return;
        if (event.vcpu().registers().rsp() != return_rsp_) {
            LOG4CXX_ERROR(logger, "BAD return RSP 0x" << std::hex << event.vcpu().registers().rsp()
                                                      << std::dec << " for " << name_);
            return;
        }

        return_tid_ = 0;
        return_rsp_ = 0;

        std::cout << "[" << event.task().pid() << ':' << event.task().tid() << "] "
                  << event.task().process_name() << '\n';
        std::cout << "    Return hit for " << name_ << std::endl;
        return_bp_.reset();
    }

    BreakpointHandler(BreakpointHandler&& src) noexcept
        : domain_(src.domain_), bp_(std::move(src.bp_)), name_(std::move(src.name_)),
          pid_(src.pid_) {
        bp_->callback(std::bind(&BreakpointHandler::breakpoint_hit, this, std::placeholders::_1));
    }

    BreakpointHandler& operator=(BreakpointHandler&& src) noexcept {
        bp_ = std::move(src.bp_);
        name_ = std::move(src.name_);
        domain_ = src.domain_;
        pid_ = src.pid_;
        bp_->callback(std::bind(&BreakpointHandler::breakpoint_hit, this, std::placeholders::_1));
        return *this;
    }

    BreakpointHandler(Domain& domain, const guest_ptr<void>& address, const std::string& name,
                      uint64_t pid)
        : domain_(&domain), name_(name), pid_(pid) {
        bp_ = domain.create_breakpoint(
            address, std::bind(&BreakpointHandler::breakpoint_hit, this, std::placeholders::_1));
    }

    ~BreakpointHandler() = default;

  public:
    Domain* domain_;
    std::shared_ptr<Breakpoint> bp_;
    std::shared_ptr<Breakpoint> return_bp_;
    std::string name_;
    uint64_t pid_;
    uint64_t return_rsp_ = 0;
    uint64_t return_tid_ = 0;
};

class CallMonitor final : public EventCallback {
  public:
    CallMonitor(const std::vector<std::string>& symbols) {
        for (const auto& symbol : symbols) {
            std::string lower_sym = symbol;
            boost::algorithm::to_lower(lower_sym);
            std::vector<std::string> parts;
            boost::algorithm::split(parts, lower_sym, boost::algorithm::is_any_of("!"),
                                    boost::algorithm::token_compress_off);
            if (parts.size() != 2) {
                throw std::invalid_argument("Invalid symbol format: " + symbol);
            }
            std::string module_name = parts[0];
            std::string symbol_name = parts[1];
            requested_symbols_[module_name].insert(symbol_name);
            LOG4CXX_DEBUG(logger, "Requested symbol: " << module_name << "!" << symbol_name);
        }
        for (const auto& kv : requested_symbols_) {
            std::string dll = kv.first;
            if (!boost::algorithm::iends_with(dll, ".dll"))
                dll += ".dll";
            requested_dlls_.insert(dll);
            LOG4CXX_DEBUG(logger, "Requested DLL: " << dll);
        }
        LOG4CXX_DEBUG(logger, "Requested symbols: " << requested_symbols_.size());
        LOG4CXX_DEBUG(logger, "Requested DLLs: " << requested_dlls_.size());
    }

    void process_event(Event& event) override {
        if (unlikely(event.os_type() != OS::Windows)) {
            return;
        }
        auto& wevent = static_cast<WindowsEvent&>(event);
        try {
            switch (event.type()) {
            case EventType::EVENT_FAST_SYSCALL:
                handle_syscall(wevent);
                break;
            case EventType::EVENT_FAST_SYSCALL_RET:
                handle_sysret(wevent);
                break;
            case EventType::EVENT_CR_WRITE:
                if (unlikely(event.cr().index() != 3)) {
                    return;
                }
                if (!initial_check_.test_and_set()) {
                    LOG4CXX_DEBUG(logger, "First CR3 write event, turning off CR3 monitoring");
                    domain->intercept_cr_writes(3, false);
                    set_breakpoints(wevent);
                }
                break;
            default:
                // Should never happen
                LOG4CXX_ERROR(logger, "Unhandled event: " << event.type());
                break;
            }
        } catch (VirtualAddressNotPresentException& ex) {
            LOG4CXX_ERROR(logger, "Unhandled Address not present error during event processing for "
                                      << ex.what());
        }
    }

    ~CallMonitor() { std::cout.flush(); }

  private:
    void handle_syscall(WindowsEvent& wevent) {
        if (!initial_check_.test_and_set()) {
            LOG4CXX_DEBUG(logger, "First syscall event, setting breakpoints");
            set_breakpoints(wevent);
        }

        switch (wevent.syscall().index()) {
        case SystemCallIndex::NtMapViewOfSection: {
            // Could be a library being mapped in.
            wevent.syscall().hook_return(true);
        }
        default:
            break;
        }
    }

    void handle_sysret(WindowsEvent& wevent) {
        switch (wevent.syscall().index()) {
        case SystemCallIndex::NtMapViewOfSection: {
            auto* handler = static_cast<nt::NtMapViewOfSection*>(wevent.syscall().handler());
            if (likely(handler->result().NT_SUCCESS())) {
                LOG4CXX_DEBUG(logger, "NtMapViewOfSection succeeded, setting breakpoints");
                set_breakpoints(wevent);
            }
        }
        default:
            break;
        }
    }

    void set_breakpoints(WindowsEvent& wevent) {
        std::lock_guard<std::mutex> lock(mtx_);

        if (all_symbols_resolved_) {
            return;
        }

        LOG4CXX_INFO(logger, "Setting breakpoints for " << wevent.task().process_name());
        auto& process = wevent.task().pcr().CurrentThread().Process();
        auto vadroot = process.VadRoot();
        if (!vadroot) {
            LOG4CXX_DEBUG(logger, "No VAD root found for " << wevent.task().process_name());
            return;
        }

        // VAD (Virtual Address Descriptor) tree: per-process kernel structure describing the
        // process's virtual address space. Each node represents one region (start/end address,
        // protection, file mapping if any, etc.). The tree is ordered by starting address;
        // VadTreeInOrder() yields regions in ascending address order.
        for (auto entry : vadroot->VadTreeInOrder()) {
            // Skip regions that are not executable
            if (!entry->Protection().isExecutable()) {
                continue;
            }

            // Get the file object for the region
            auto file_object = entry->FileObject();
            if (!file_object) {
                continue;
            }

            // Get the filename for the region
            const std::string filename = file_object->FileName();

            // Check if the filename matches any of the requested DLLs
            std::string matched_dll;
            for (const auto& dll : requested_dlls_) {
                if (boost::algorithm::iends_with(filename, dll)) {
                    matched_dll = dll;
                    break;
                }
            }

            // Skip if we've already processed this DLL
            if (matched_dll.empty() || found_dlls_.count(matched_dll)) {
                continue;
            }

            // Get the module name from the DLL name
            std::string module_name = matched_dll;
            if (boost::algorithm::iends_with(module_name, ".dll")) {
                module_name.resize(module_name.size() - 4);
            }

            // Check if the module name matches any of the requested symbols
            auto it = requested_symbols_.find(module_name);
            if (it == requested_symbols_.end()) {
                continue;
            }

            // Get the symbols for the module
            const std::set<std::string>& patterns = it->second;
            LOG4CXX_DEBUG(logger, "Found symbols for " << module_name << ": " << patterns.size());

            try {
                // Load the PE for the module
                auto lib =
                    pe::PE::make_unique(guest_ptr<void>(wevent.vcpu(), entry->StartingAddress()));
                auto& pdb = lib->pdb();
                LOG4CXX_INFO(logger, "Loaded PE for " << matched_dll);

                // Iterate over the global symbols in the PDB
                for (const auto& symbol : pdb.global_symbols()) {
                    if (!symbol->function() && !symbol->code()) {
                        continue;
                    }

                    bool matched = false;
                    for (const auto& pattern : patterns) {
                        if (symbol_matches_pattern(pattern, symbol->name())) {
                            matched = true;
                            break;
                        }
                    }
                    if (!matched) {
                        continue;
                    }

                    try {
                        guest_ptr<void> ptr(wevent.vcpu(),
                                            entry->StartingAddress() + symbol->image_offset());
                        breakpoints_.emplace_back(wevent.domain(), ptr, symbol->name(),
                                                  process.UniqueProcessId());
                        LOG4CXX_INFO(logger, "Added breakpoint for " << matched_dll << "!"
                                                                     << symbol->name());
                    } catch (VirtualAddressNotPresentException& ex) {
                        LOG4CXX_DEBUG(logger, "Address not present for " << matched_dll << "!"
                                                                         << symbol->name());
                    }
                }
            } catch (VirtualAddressNotPresentException& ex) {
                LOG4CXX_DEBUG(logger, "PE not present for " << matched_dll);
                continue;
            }

            found_dlls_.insert(matched_dll);
            if (found_dlls_.size() == requested_dlls_.size()) {
                domain->intercept_system_calls(false);
                all_symbols_resolved_ = true;
                return;
            }
        }
    }

  private:
    std::mutex mtx_;
    bool all_symbols_resolved_ = false;
    std::atomic_flag initial_check_ = false;
    std::unordered_map<std::string, std::set<std::string>> requested_symbols_;
    std::set<std::string> requested_dlls_;
    std::set<std::string> found_dlls_;
    std::set<std::string> found_symbols_;
    std::vector<BreakpointHandler> breakpoints_;
};

int main(int argc, char** argv) {
    po::options_description desc("Options");
    std::string domain_name;
    std::string process_name;
    std::vector<std::string> symbols;

    // clang-format off
    desc.add_options()
      ("domain,D", po::value<std::string>(&domain_name)->required(), "The domain name or ID attach to")
      ("procname,P", po::value<std::string>(&process_name)->required(), "A process name to filter for")
      ("symbol,s", po::value<std::vector<std::string>>(&symbols), "Symbols in the form Module!Symbol to breakpoint. Default: ntdll!Nt*")
      ("help", "Display program help");
    // clang-format on

    std::cout.sync_with_stdio(false);

    po::variables_map vm;
    parse_program_options(argc, argv, desc, vm);

    auto hypervisor = Hypervisor::instance();
    signal(SIGINT, &sig_handler);
    domain = hypervisor->attach_domain(domain_name);

    if (!domain->detect_guest()) {
        std::cerr << "Failed to detect guest OS\n";
        return 1;
    }
    if (domain->guest()->os() != OS::Windows) {
        std::cerr << "ivcallmon only supports Windows guests\n";
        return 1;
    }
    if (!process_name.empty()) {
        domain->task_filter().add_name(process_name);
    }
    if (symbols.empty()) {
        symbols.push_back("ntdll!Nt*");
    }

    auto* guest = static_cast<WindowsGuest*>(domain->guest());
    domain->system_call_filter().enabled(true);
    guest->set_system_call_filter(domain->system_call_filter(), SystemCallIndex::NtMapViewOfSection,
                                  true);
    domain->intercept_system_calls(true);
    domain->intercept_cr_writes(3, true);

    CallMonitor monitor(symbols);
    domain->poll(monitor);

    return 0;
}

void parse_program_options(int argc, char** argv, po::options_description& desc,
                           po::variables_map& vm) {
    try {
        po::store(po::parse_command_line(argc, argv, desc), vm);
        if (vm.count("help")) {
            std::cout << "ivcallmon - Watch guest library calls" << '\n';
            std::cout << desc << '\n';
            exit(0);
        }
        po::notify(vm);
    } catch (po::error& e) {
        std::cerr << "ERROR: " << e.what() << std::endl << std::endl;
        std::cerr << desc << std::endl;
        exit(1);
    }
}
