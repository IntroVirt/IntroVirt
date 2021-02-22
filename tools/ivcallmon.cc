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
        // std::cout << "    Return RSP 0x" << std::hex << return_rsp_ << '\n' << std::dec;

        GuestVirtualAddress return_address_ptr(event.vcpu(), event.vcpu().registers().rsp());
        GuestVirtualAddress return_address(
            return_address_ptr.create(*guest_ptr<uint64_t>(return_address_ptr)));

        // std::cout << "    Return RIP " << return_address << '\n';

        return_bp_ = domain_->create_breakpoint(
            return_address, std::bind(&BreakpointHandler::return_hit, this, std::placeholders::_1));

        std::cout.flush();
    }

    void return_hit(Event& event) {
        if (event.task().tid() != return_tid_)
            return;
        if (event.vcpu().registers().rsp() != return_rsp_) {
            std::cout << "    BAD return RSP 0x" << std::hex << event.vcpu().registers().rsp()
                      << std::dec << " for " << name_ << "\n";
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

    BreakpointHandler(Domain& domain, const GuestAddress& address, const std::string& name,
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
    void process_event(Event& event) override {
        switch (event.type()) {
        case EventType::EVENT_CR_WRITE:
            if (event.cr().index() != 3)
                return;
            break;
        default:
            std::cout << "Unhandled event: " << event.type() << '\n';
            break;
        }

        std::lock_guard<std::mutex> lock(mtx_);

        if (ready_)
            return;

        auto& process = static_cast<WindowsEvent&>(event).task().pcr().CurrentThread().Process();
        auto vadroot = process.VadRoot();
        if (!vadroot)
            return;

        for (auto entry : vadroot->VadTreeInOrder()) {
            if (!entry->Protection().isExecutable())
                continue;
            auto file_object = entry->FileObject();
            if (!file_object)
                continue;

            if (boost::algorithm::ends_with(file_object->FileName(), "ntdll.dll")) {
                // Found it
                // Breakpoint everything exported
                auto lib = pe::PE::make_unique(entry->StartingAddress());
                auto& pdb = lib->pdb();
                for (const auto& symbol : pdb.global_symbols()) {
                    if (symbol->function() || symbol->code()) {
                        if (!boost::starts_with(symbol->name(), "Nt"))
                            continue;
                        if (symbol->name() == "KiUserCallbackDispatch" ||
                            symbol->name() == "KiUserCallbackDispatcher")
                            continue;
                        std::cout << "Adding breakpoint for " << symbol->name() << '\n';
                        try {
                            breakpoints_.emplace_back(
                                event.domain(), entry->StartingAddress() + symbol->image_offset(),
                                symbol->name(), process.UniqueProcessId());
                        } catch (VirtualAddressNotPresentException& ex) {
                            std::cout << "  Not present!\n";
                        }
                    }
                }

                if (flush_)
                    std::cout.flush();

                event.domain().intercept_cr_writes(3, false);
                ready_ = true;
                return;
            }
        }
    }

    CallMonitor(bool flush) : flush_(flush) {}
    ~CallMonitor() { std::cout.flush(); }

  private:
    std::mutex mtx_;
    const bool flush_;
    bool ready_ = false;
    std::vector<BreakpointHandler> breakpoints_;
};

int main(int argc, char** argv) {
    po::options_description desc("Options");
    std::string domain_name;
    std::string process_name;

    // clang-format off
    desc.add_options()
      ("domain,D", po::value<std::string>(&domain_name)->required(), "The domain name or ID attach to")
      ("procname", po::value<std::string>(&process_name)->required(), "A process name to filter for")
      ("no-flush", "Don't flush the output buffer after each event")
      ("help", "Display program help");
    // clang-format on

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
    if (!process_name.empty())
        domain->task_filter().add_name(process_name);

    // Enable system call hooking on all vcpus
    domain->intercept_cr_writes(3, true);

    // Start the poll
    CallMonitor monitor(!vm.count("no-flush"));
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
            std::cout << "ivcallmon - Watch guest library calls" << '\n';
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
