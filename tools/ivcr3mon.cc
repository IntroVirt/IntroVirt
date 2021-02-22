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

namespace po = boost::program_options;

void parse_program_options(int argc, char** argv, po::options_description& desc,
                           po::variables_map& vm);

bool interrupted = false;
std::unique_ptr<Domain> domain;

void sig_handler(int signum) {
    interrupted = true;
    domain->interrupt();
}

class CR3Monitor final : public EventCallback {
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

        const Vcpu& vcpu = event.vcpu();
        const Registers& regs = vcpu.registers();

        const auto cr3 = regs.cr3();
        const auto pid = event.task().pid();
        const auto tid = event.task().tid();
        const auto name = event.task().process_name();

        // Lock so that we don't mess up stdout writes
        std::lock_guard lock(mtx_);

        if (!json_) {
            std::cout << "Vcpu " << vcpu.id() << ": 0x" << std::hex << cr3 << " -> 0x"
                      << event.cr().value() << std::dec << '\n';
            std::cout << "    [" << pid << ':' << tid << "] ";
            std::cout << name << '\n';
        } else {
            std::cout << event.json() << '\n';
        }

        if (flush_)
            std::cout.flush();
    }

    CR3Monitor(bool flush, bool json) : flush_(flush), json_(json) {}
    ~CR3Monitor() { std::cout.flush(); }

  private:
    std::mutex mtx_;
    const bool flush_;
    const bool json_;
};

int main(int argc, char** argv) {
    po::options_description desc("Options");
    std::string domain_name;

    // clang-format off
    desc.add_options()
      ("domain,D", po::value<std::string>(&domain_name)->required(), "The domain name or ID attach to")
      ("no-flush", "Don't flush the output buffer after each event")
      ("json", "Output JSON format")
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

    // Enable CR3 hooking on all vcpus
    domain->intercept_cr_writes(3, true);

    // Start the poll
    CR3Monitor monitor(!vm.count("no-flush"), vm.count("json"));
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
            std::cout << "ivcr3mon - Watch guest CR3 writes" << '\n';
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