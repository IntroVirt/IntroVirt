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
#include <cstring>
#include <iostream>
#include <memory>
#include <sys/types.h>

using namespace introvirt;
using namespace introvirt::windows;
using namespace introvirt::windows::nt;

using namespace std;

namespace po = boost::program_options;

void parse_program_options(int argc, char** argv, po::options_description& desc,
                           po::variables_map& vm);

bool interrupted = false;
std::unique_ptr<Domain> domain;

void sig_handler(int signum) {
    interrupted = true;
    domain->interrupt();
}

class ReadFileTool final : public EventCallback {
  public:
    void copy() {
        result_ = 1;

        // Allocate some structures in the guest
        auto src_path = inject::allocate<nt::UNICODE_STRING>("\\??\\" + src_path_);
        auto object_attributes = inject::allocate<nt::OBJECT_ATTRIBUTES>();
        auto io_status_block = inject::allocate<nt::IO_STATUS_BLOCK>();

        // Set the ObjectName in OBJECT_ATTRIBUTES
        object_attributes->ObjectNamePtr(src_path);
        object_attributes->Attributes(OBJECT_ATTRIBUTES::OBJ_CASE_INSENSITIVE);

        // Open the source file in the guest
        uint64_t src_file;
        nt::NTSTATUS result = inject::system_call<nt::NtCreateFile>(
            src_file,                                               // FileHandle
            SYNCHRONIZE | GENERIC_READ,                             // DesiredAccess
            object_attributes,                                      // ObjectAttributes
            io_status_block,                                        // IoStatusBlock
            nullptr,                                                // AllocationSize
            FILE_ATTRIBUTE_NORMAL,                                  // FileAttributes
            FILE_SHARE_ACCESS(0),                                   // ShareAccess
            FILE_OPEN,                                              // CreateDisposition
            FILE_NON_DIRECTORY_FILE | FILE_SYNCHRONOUS_IO_NONALERT, // CreateOptions
            NullGuestAddress(),                                     // pEaBuffer
            0                                                       // EaLength
        );

        if (!result.NT_SUCCESS()) {
            std::cout << "Failed to open source file: " << result << '\n';
            return;
        }

        // Open the destination file
        FILE* dst_file = fopen(dst_path_.c_str(), "w");
        if (!dst_file) {
            std::cout << "Failed to open destination file: " << strerror(errno) << '\n';
            return;
        }

        // Allocate a transfer buffer in the guest
        constexpr size_t BUFFER_SIZE = 1048576 * 2; // 2 MiB
        auto buffer = inject::allocate<char[]>(BUFFER_SIZE);

        // Read data into it until we hit EOF
        while (true) {
            // Read from the file into our buffer
            result = inject::system_call<nt::NtReadFile>(src_file, 0, NullGuestAddress(),
                                                         NullGuestAddress(), io_status_block,
                                                         buffer, BUFFER_SIZE, nullptr, nullptr);
            if (result.NT_SUCCESS()) {
                // The data was successfully read
                // Transfer the buffer to our destination file
                if (fwrite(buffer, 1, io_status_block->Information(), dst_file) < 0) {
                    std::cout << "Failed to write to destination file: " << strerror(errno) << '\n';
                    break;
                }
                // Transfer the next chunk
                continue;
            }

            if (result.code() == STATUS_END_OF_FILE) {
                // EOF reached
                result_ = 0;
                break;
            }

            std::cout << "Failed to read from source file: " << result << '\n';
            break;
        }

        // Close the source file
        result = inject::system_call<NtClose>(src_file);
        if (!result.NT_SUCCESS()) {
            std::cout << "Failed to close source file: " << result << '\n';
        }

        // Close the destination file
        fclose(dst_file);

        // TODO: Query the source file size, we need to implement FILE_STANDARD_INFORMATION
        /*
        ProgressBar progressBar;
        progressBar.draw(0.0f);
        progressBar_.draw((bytesRead_ * 100) / srcFileSize_);
        progressBar_.complete();
        */
    }

    void process_event(Event& event) override {
        if (unlikely(event.type() == EventType::EVENT_SHUTDOWN ||
                     event.type() == EventType::EVENT_REBOOT)) {
            exit(64);
        }

        if (event.type() == EventType::EVENT_FAST_SYSCALL) {
            if (copy_started_.test_and_set() == 0) {
                copy();
                event.domain().interrupt();
            }
        }
    }

    ReadFileTool(const std::string& src_path, const std::string& dst_path)
        : src_path_(src_path), dst_path_(dst_path) {}

    int result() const { return result_; }

  private:
    const std::string src_path_;
    const std::string dst_path_;

    int result_;

    std::atomic_flag copy_started_ = false;
};

int main(int argc, char** argv) {
    po::options_description desc("Options");
    std::string domain_name;
    std::string process_name;
    std::string source_file;
    std::string dest_file;

    // clang-format off
    desc.add_options()
      ("domain,D", po::value<std::string>(&domain_name)->required(), "The domain name or ID attach to")
      ("source_file,s", po::value<std::string>(&source_file)->required(), "The path to the source file in the guest")
      ("dest_file,d", po::value<std::string>(&dest_file)->required(), "The destination file to write")
      ("process_name,P", po::value<std::string>(&process_name)->default_value("explorer"), "The name of a process to hijack")
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

    // Set our process name filter
    domain->task_filter().add_name(process_name);

    // Enable system call hooking on all vcpus
    domain->intercept_system_calls(true);

    // Start the poll
    ReadFileTool tool(source_file, dest_file);
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
            std::cout << "ivreadfile - Write a file into the guest" << '\n';
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