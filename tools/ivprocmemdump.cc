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

#include <cerrno>
#include <csignal>
#include <cstring>
#include <iostream>
#include <memory>
#include <thread>

using namespace introvirt;
using namespace introvirt::windows;
using namespace introvirt::windows::nt;
using namespace introvirt::windows::kernel32;
using namespace introvirt::windows::condrv;

namespace po = boost::program_options;

void parse_program_options(int argc, char** argv, po::options_description& desc,
                           po::variables_map& vm);

std::atomic_flag interrupted = false;
std::unique_ptr<Domain> domain;

void sig_handler(int signum) {
    if (interrupted.test_and_set() == false) {
        std::cerr << "Interrupted by signal, exiting...\n";
        domain->interrupt();
    }
}

class MemDumpTool final : public EventCallback {
  public:
    MemDumpTool(const std::string& output_file) : output_file_(output_file) {}

    void dump(Event& event) {
        auto& wevent = static_cast<WindowsEvent&>(event);
        auto& current_process = wevent.task().pcr().CurrentThread().Process();

        const uint64_t pid = current_process.UniqueProcessId();

        // Try to open the process (which should be ourselves)
        auto object_attributes = inject::allocate<nt::OBJECT_ATTRIBUTES>();
        auto client_id = inject::allocate<nt::CLIENT_ID>(pid, 0);
        const uint32_t access_mask =
            PROCESS_VM_READ | PROCESS_VM_OPERATION | PROCESS_QUERY_INFORMATION;

        uint64_t process_handle;
        auto result = inject::system_call<nt::NtOpenProcess>(process_handle, access_mask,
                                                             object_attributes, client_id);

        if (!result.NT_SUCCESS()) {
            std::cerr << "Failed to open PID " << pid << ": " << result << '\n';
            return;
        }

        // Find the newly opened process in the handle table
        auto ObjectTable = current_process.ObjectTable();
        auto process = ObjectTable->ProcessObject(process_handle);
        std::cout << "Opened process " << process->ImageFileName() << std::endl;

        auto mmvad = process->VadRoot();
        if (!mmvad) {
            std::cerr << "MMVAD was null\n";
            return;
        }

        auto mbi = inject::allocate<MEMORY_BASIC_INFORMATION>();

        std::vector<std::pair<GuestVirtualAddress, GuestVirtualAddress>> dump_regions;
        for (const auto& entry : mmvad->VadTreeInOrder()) {
            // Skip regions that are completely inaccessible
            if ((entry->Protection().value() & PAGE_PROTECTION::PAGE_NOACCESS))
                continue;

            if (pid == current_process.UniqueProcessId()) {
                // Reading from the process itself, so we have to skip anything we allocated
                if (object_attributes.address().page_number() == entry->StartingVpn())
                    continue;
                if (client_id.address().page_number() == entry->StartingVpn())
                    continue;
                if (mbi.address().page_number() == entry->StartingVpn())
                    continue;
            }

            GuestVirtualAddress addr;
            for (addr = entry->StartingAddress(); addr < entry->EndingAddress();) {

                // TODO: We shouldn't need injection to figure this information out
                auto result = inject::system_call<nt::NtQueryVirtualMemory>(
                    process_handle, addr, MemoryBasicInformation, mbi, mbi->buffer_size(), nullptr);

                if (!result.NT_SUCCESS()) {
                    std::cerr << "NtQueryVirtualMemory failed for " << addr << ": " << result
                              << '\n';

                    addr += x86::PageDirectory::PAGE_SIZE;
                    continue;
                }

                if (mbi->State().MEM_COMMIT() == false ||
                    (mbi->Protect() &
                     (PAGE_PROTECTION::PAGE_GUARD | PAGE_PROTECTION::PAGE_NOACCESS)) != 0 ||
                    (mbi->Type() & (MEM_IMAGE | MEM_MAPPED | MEM_PRIVATE)) == 0) {
                    // std::cout << "Skipping region 0x" << addr << std::endl;
                    addr += mbi->RegionSize();
                    continue;
                }

                if (addr.value() == 0x000000000C2F1000) {
                    std::cerr << "Yeah I'm here\n";
                    mbi->write(std::cerr, "");
                }

                if (unlikely(addr.value() != mbi->BaseAddress())) {
                    std::cerr << "Base address mismatch!! Ahh!!!\n";
                }

                // This region is good, add it
                dump_regions.push_back(std::make_pair(addr, addr + mbi->RegionSize()));

                // Skip past the region
                addr += mbi->RegionSize();
            }
        }

        int count = 0;
        constexpr int BufferSize = x86::PageDirectory::PAGE_SIZE * 4;
        auto buffer = inject::allocate<char[]>(BufferSize);

        // Things are looking good, open our output file
        FILE* output = fopen64(output_file_.c_str(), "wb");
        if (!output) {
            std::cerr << "Failed to open output file\n";
            goto bad_fopen;
        }

        // Now we will try to read them all
        for (const auto& region : dump_regions) {
            for (auto addr = region.first; addr < region.second;) {
                const uint32_t copy_size = std::min(region.second - addr, BufferSize);

                uint32_t ResultLength = 0;
                auto result = inject::system_call<nt::NtReadVirtualMemory>(
                    process_handle, addr, buffer, x86::PageDirectory::PAGE_SIZE, &ResultLength);

                if (!result.NT_SUCCESS() || ResultLength != x86::PageDirectory::PAGE_SIZE) {
                    std::cerr << "Failed to copy " << addr << ": " << result << '\n';
                    addr += x86::PageDirectory::PAGE_SIZE;
                    continue;
                }

                // Write it to our file
                off64_t offset = addr.value();

                // std::cout << "Seeking to " << std::hex << offset << std::endl << std::dec;
                if (fseeko64(output, offset, SEEK_SET) < 0) {
                    // std::cerr << "Bad fseek: " << strerror(errno) << std::endl;
                }

                fwrite(buffer, 1, copy_size, output);

                count += (copy_size / x86::PageDirectory::PAGE_SIZE);
                addr += copy_size;
            }
        }
        fclose(output);
        std::cerr << "Done!\n";
        std::cerr << "Copied " << count << " pages\n";
        result_ = 0;

    bad_fopen:
        result = inject::system_call<nt::NtClose>(process_handle);
        if (!result.NT_SUCCESS())
            std::cerr << "Failed to close target process: " << result << '\n';
    }

    void process_event(Event& event) override {
        if (unlikely(event.type() == EventType::EVENT_SHUTDOWN ||
                     event.type() == EventType::EVENT_REBOOT)) {
            result_ = 64;
            return;
        }

        // We only want one instance
        if (started_.test_and_set() == true)
            return;

        // No more events, please.
        event.domain().intercept_system_calls(false);
        dump(event);
        event.domain().interrupt();
    }

    int result() const { return result_; }

  private:
    const std::string output_file_;
    std::atomic_flag started_ = false;
    uint8_t result_ = 1;
};

int main(int argc, char** argv) {
    po::options_description desc("Options");
    std::string domain_name;
    std::string process_name;
    std::string output;

    // clang-format off
    desc.add_options()
      ("domain,D", po::value<std::string>(&domain_name)->required(), "The domain name or ID attach to")    
      ("procname,P", po::value<std::string>(&process_name)->required(), "The name of a process to hijack")
      ("output,o", po::value<std::string>(&output)->required(), "A path to an output file")
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

    if (domain->guest()->os() != OS::Windows) {
        std::cerr << "Unsupported OS: " << domain->guest()->os() << '\n';
        return 1;
    }

    domain->task_filter().add_name(process_name);

    // Enable system call hooking on all vcpus
    domain->intercept_system_calls(true);

    // Start the poll
    MemDumpTool tool(output);
    domain->poll(tool);
    return tool.result();
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
            std::cout << "ivexec - Execute a file in the guest" << '\n';
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