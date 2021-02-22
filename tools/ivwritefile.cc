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
#include <string>
#include <string_view>
#include <sys/stat.h>
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

static std::string get_filename_from_path(std::string_view src) {
    const size_t slashPos = src.rfind('/');
    string fileName;
    if (slashPos != string::npos) {
        fileName = src.substr(slashPos + 1);
    } else {
        fileName = src;
    }
    return fileName;
}

class WriteFileTool final : public EventCallback {
  public:
    void copy() {
        result_ = 1;

        // Open the source file
        FILE* src_file = fopen(src_path_.c_str(), "r");
        if (!src_file) {
            std::cout << "Failed to open source file: " << strerror(errno) << '\n';
            return;
        }

        // Try to get the size of the source file
        struct stat src_stat;
        if (fstat(fileno(src_file), &src_stat) != 0) {
            std::cerr << "Failed to stat source file: " << strerror(errno) << '\n';
            return;
        }

        // Allocate some structures in the guest
    retry:
        auto dst_path = inject::allocate<nt::UNICODE_STRING>("\\??\\" + dst_path_);
        auto object_attributes = inject::allocate<nt::OBJECT_ATTRIBUTES>();
        auto io_status_block = inject::allocate<nt::IO_STATUS_BLOCK>();

        // Set the ObjectName in OBJECT_ATTRIBUTES
        object_attributes->ObjectNamePtr(dst_path);
        object_attributes->Attributes(OBJECT_ATTRIBUTES::OBJ_CASE_INSENSITIVE);

        // Open the destination file in the guest
        uint64_t dst_file;
        nt::NTSTATUS result = inject::system_call<nt::NtCreateFile>(
            dst_file,                                               // FileHandle
            SYNCHRONIZE | GENERIC_WRITE,                            // DesiredAccess
            object_attributes,                                      // ObjectAttributes
            io_status_block,                                        // IoStatusBlock
            nullptr,                                                // AllocationSize
            FILE_ATTRIBUTE_NORMAL,                                  // FileAttributes
            FILE_SHARE_ACCESS(0),                                   // ShareAccess
            FILE_SUPERSEDE,                                         // CreateDisposition
            FILE_NON_DIRECTORY_FILE | FILE_SYNCHRONOUS_IO_NONALERT, // CreateOptions
            NullGuestAddress(),                                     // pEaBuffer
            0                                                       // EaLength
        );

        if (result == STATUS_FILE_IS_A_DIRECTORY) {
            // User specified a directory, assume they want to put the file inside.
            dst_path_ = dst_path_ + '\\' + get_filename_from_path(src_path_);
            goto retry;
        }

        if (!result.NT_SUCCESS()) {
            std::cout << "Failed to open destination file: " << result << '\n';
            return;
        }

        // Allocate a transfer buffer in the guest
        constexpr size_t BUFFER_SIZE = 1048576 * 2; // 2 MiB
        auto buffer = inject::allocate<char[]>(BUFFER_SIZE);

        // Read data into it until we hit EOF
        ProgressBar progress;
        size_t bytes_written = 0;
        while (true) {
            // Read from the source file into our buffer
            const int count = fread(buffer, 1, BUFFER_SIZE, src_file);
            if (unlikely(count < 0)) {
                std::cout << "Failed to read from source file: " << strerror(errno) << '\n';
                break;
            }
            if (count == 0) {
                // Reached end of file
                break;
            }

            result = inject::system_call<nt::NtWriteFile>(dst_file, 0, NullGuestAddress(),
                                                          NullGuestAddress(), io_status_block,
                                                          buffer, count, nullptr, nullptr);

            if (result.NT_SUCCESS()) {
                // The data was successfully written
                // Transfer the next chunk
                bytes_written += count;
                if (progress_bar_)
                    progress.draw((bytes_written * 100.0f) / src_stat.st_size);
                continue;
            }

            std::cout << "Failed to write to destination file: " << result << '\n';
            break;
        }

        // Close the destination file
        result = inject::system_call<NtClose>(dst_file);
        if (!result.NT_SUCCESS()) {
            std::cout << "Failed to close destination file: " << result << '\n';
        }

        if (progress_bar_)
            progress.complete();

        // Close the source file
        fclose(src_file);
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

    WriteFileTool(const std::string& src_path, const std::string& dst_path, bool progress_bar)
        : src_path_(src_path), dst_path_(dst_path), progress_bar_(progress_bar) {}

    int result() const { return result_; }

  private:
    const std::string src_path_;
    std::string dst_path_;
    const bool progress_bar_;

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
      ("source_file,s", po::value<std::string>(&source_file)->required(), "The path to the source file")
      ("dest_file,d", po::value<std::string>(&dest_file)->required(), "The destination file path to write in the guest")
      ("process_name,P", po::value<std::string>(&process_name)->default_value("explorer"), "The name of a process to hijack")
      ("progress", "Display a progress bar")
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

    // If the file ends in a backslash, treat it like a directory and append the source file
    if (boost::ends_with(dest_file, "\\")) {
        dest_file += get_filename_from_path(source_file);
    }

    // Start the poll
    WriteFileTool tool(source_file, dest_file, vm.count("progress"));
    domain->poll(tool);
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
            std::cout << "ivwritefile - Write a file into the guest" << '\n';
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