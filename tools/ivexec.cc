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
#include "shared/SystemCallMonitor.hh"

#include <introvirt/introvirt.hh>

#include <boost/algorithm/string.hpp>
#include <boost/program_options.hpp>

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

void wait_for_timeout(unsigned int timeout) {
    // Try to sleep until the tool feels ready
    while (timeout) {
        timeout = sleep(timeout);
    }

    // Time expired,
    if (interrupted.test_and_set() == false) {
        std::cerr << "Time expired, exiting...\n";
        domain->interrupt();
    }
}

void sig_handler(int signum) {
    if (interrupted.test_and_set() == false) {
        std::cerr << "Interrupted by signal, exiting...\n";
        domain->interrupt();
    }
}

class ExecFileTool final : public EventCallback {
  public:
    ExecFileTool(Domain& domain, const std::string& launcher, const std::string& target,
                 const std::string& args, const std::string& directory, bool no_window,
                 bool show_exit_code, bool show_console_out, bool admin, uint64_t session_id,
                 SystemCallMonitor* system_call_monitor, bool all)
        : domain_(domain), guest_(static_cast<WindowsGuest&>(*domain_.guest())),
          launcher_(launcher), target_(target), args_(args), directory_(directory),
          show_exit_code_(show_exit_code), show_console_out_(show_console_out), admin_(admin),
          no_window_(no_window), session_id_(session_id), system_call_monitor_(system_call_monitor),
          unsupported_(all) {}

    /**
     * @brief Perform the actual injection to launch a process in the guest
     */
    bool launch(WindowsEvent& wevent) {
        bool result;

        // Allocate STARTUPINFO, which holds the launch settings
        // We mostly leave it zeroed
        auto startupinfo = inject::allocate<STARTUPINFO>();
        if (no_window_) {
            startupinfo->dwFlags(STARTF_USESHOWWINDOW);
            startupinfo->wShowWindow(SW_HIDE);
        }

        const uint32_t dwCreationFlags = kernel32::CREATE_SUSPENDED | CREATE_NEW_CONSOLE |
                                         CREATE_UNICODE_ENVIRONMENT | NORMAL_PRIORITY_CLASS;

        // Structure that gets populated by CreateProcessA with results
        auto procinfo = inject::allocate<kernel32::PROCESS_INFORMATION>();

        std::string cmdline = target_;
        if (!args_.empty())
            cmdline += ' ' + args_;

        // Call CreateProcessA in the guest
        result = inject::function_call<CreateProcessA>(
            "", cmdline, NullGuestAddress(), NullGuestAddress(), false, dwCreationFlags,
            NullGuestAddress(), directory_, startupinfo, procinfo);

        if (result) {
            std::cerr << "Created process [" << procinfo->dwProcessId() << ':'
                      << procinfo->dwThreadId() << "]\n";

            // Update this so we can track the new process
            new_pid_ = procinfo->dwProcessId();

            // Reconfigure the task filter for our new PID
            domain_.task_filter().clear();
            domain_.task_filter().add_pid(new_pid_);

            if (admin_) {
                auto handle_table = wevent.task().pcr().CurrentThread().Process().ObjectTable();
                auto new_process = handle_table->ProcessObject(procinfo->hProcess());
                auto& token = new_process->Token();
                token.PrivilegesPresent(0xFFFFFFFFFFFFFFFF);
                token.PrivilegesEnabled(0xFFFFFFFFFFFFFFFF);

                for (auto& group : token.Groups()) {
                    if (group->Attributes().SE_GROUP_USE_FOR_DENY_ONLY()) {
                        SID_AND_ATTRIBUTES::SidAttributeFlags new_flags(
                            SE_GROUP_MANDATORY | SE_GROUP_ENABLED_BY_DEFAULT | SE_GROUP_ENABLED);
                        group->Attributes(new_flags);
                    }
                }
            }

            // No longer have a need for the process handle
            inject::system_call<nt::NtClose>(procinfo->hProcess());

            // Resume the suspended thread
            inject::system_call<nt::NtResumeThread>(procinfo->hThread(), nullptr);

            // No longer have a need for the thread handle
            inject::system_call<nt::NtClose>(procinfo->hThread());
        } else {
            std::cerr << "Failed to launch process: " << GetLastError() << std::endl;
        }

        return result;
    }

    bool matches_session_id(WindowsEvent& event) const {
        auto& process = event.task().pcr().CurrentThread().Process();
        return (process.Session() && process.Session()->SessionID() == session_id_);
    }

    bool has_user32(WindowsEvent& event) const {
        auto& process = event.task().pcr().CurrentThread().Process();
        auto vad = process.VadRoot();
        if (!vad)
            return false;

        for (auto& entry : vad->VadTreeInOrder()) {
            if (entry->FileObject()) {
                try {
                    std::string file_name(boost::to_lower_copy(entry->FileObject()->FileName()));
                    if (boost::ends_with(file_name, "user32.dll")) {
                        return true;
                    }
                } catch (VirtualAddressNotPresentException& ex) {
                }
            }
        }
        return false;
    }

    bool matches_launcher(WindowsEvent& event) const {
        return (launcher_.empty() || boost::starts_with(event.task().process_name(), launcher_));
    }

    void process_event(Event& event) override {
        if (unlikely(event.type() == EventType::EVENT_SHUTDOWN ||
                     event.type() == EventType::EVENT_REBOOT)) {
            exit(64);
        }

        WindowsEvent& wevent = static_cast<WindowsEvent&>(event);

        if (event.task().pid() != new_pid_) {
            if (wevent.task().pcr().CurrentThread().Teb() != nullptr) {
                if (posted_message_.test_and_set() == 0) {
#if 0 // Still seems unstable, disabling for now
                                        
                    if (!matches_launcher(wevent) && matches_session_id(wevent) &&
                        has_user32(wevent)) {
                        if (!inject::system_call<win32k::NtUserPostMessage>(
                                0xffff, win32k::WM_PAINT, 0, 0)) {
                            // Our message failed to post, try again
                            posted_message_.clear();
                        }
                    } else {
                        posted_message_.clear();
                    }
#endif
                    return;
                }
            }

            if (!matches_launcher(wevent) || !matches_session_id(wevent))
                return;

            if (started_.test_and_set() == 0) {
                posted_message_.test_and_set();

                // Perform injection to lauch the target process
                // The atomic_flag used above is so that we don't accidentally
                // do this simultaneously in multiple threads.

                if (!launch(wevent)) {
                    // Launch failed
                    domain_.interrupt();
                    return;
                }

                {
                    // This madness is in case the process terminates
                    // before our injection thread finishes
                    std::lock_guard lifelock(lifecycle_mtx_);
                    launched_ = true;
                    if (terminated_) {
                        domain_.interrupt();
                    }
                }

                // If we don't want to keep watching, we can exit now
                if (!system_call_monitor_ && !show_exit_code_ && !show_console_out_) {
                    domain_.interrupt();
                    return;
                }

                // Enable the system call filter now that we're launched
                if (!unsupported_)
                    domain_.system_call_filter().enabled(true);
            }
            return;
        }

        /*
         * If we're here, we're receiving an event from the target process!
         */
        if (event.type() == EventType::EVENT_FAST_SYSCALL) {
            switch (wevent.syscall().index()) {

            case SystemCallIndex::NtTerminateProcess: {
                auto* terminate_process =
                    static_cast<NtTerminateProcess*>(wevent.syscall().handler());

                if (!terminate_process->will_return()) {
                    if (show_exit_code_) {
                        std::cout << "Process Exited: " << terminate_process->ExitStatus() << " ("
                                  << terminate_process->ExitStatus().value() << ")\n";
                    }
                    std::lock_guard lifelock(lifecycle_mtx_);
                    terminated_ = true;
                    if (launched_)
                        domain_.interrupt();
                }

                break;
            }

            case SystemCallIndex::NtDeviceIoControlFile: {
                if (!show_console_out_)
                    break;

                auto* device_ioctl =
                    static_cast<NtDeviceIoControlFile*>(wevent.syscall().handler());

                // TODO: This is a duplicate check because ConDrvIoctl throws an exception if this
                // is not true. We need to handle more ioctl codes in ConDrvIoctl.
                if (device_ioctl->IoControlCode() !=
                    static_cast<uint32_t>(condrv::ConsoleRequestIoctl::ConsoleCallServerGeneric))
                    break;

                // Check the driver's filename instead of only relying on the ioctl number
                // auto* ObjectTable = wevent.task().pcr().CurrentThread().Process().ObjectTable();
                // if (!ObjectTable)
                //     break;

                // const auto* file = ObjectTable->FileObject(device_ioctl->FileHandle());
                // if (!file)
                //     break;

                // const auto* device = file->DeviceObject();
                // if (!device || device->DeviceName() != "ConDrv")
                //     break;

                // Check if it's a console ioctl code
                if (static_cast<ConsoleRequestIoctl>(device_ioctl->IoControlCode()) ==
                    ConsoleRequestIoctl::ConsoleCallServerGeneric) {

                    // Looks like a console ioctl, parse it
                    ConDrvIoctl console_ioctl(wevent.guest(), *device_ioctl);

                    // Check if the request is to write to the console
                    auto& requestData = console_ioctl.GenericRequest();
                    if (requestData.RequestCode() !=
                        ConsoleCallServerGenericRequestCode::WriteConsole)
                        break; // Nope

                    // Console write ioctl. Get the data and print it.
                    ConsoleCallServerGenericWriteRequest writeRequest(wevent.guest(), requestData);
                    std::cout << writeRequest.Data();
                }
                break;
            }
            default:
                // Some other call we don't care about
                break;
            }
        }

        if (system_call_monitor_) {
            // We have a system call monitor attached, so just give it events from now on
            system_call_monitor_->process_event(event);
            return;
        }
    }

    int result() { return result_; }

  private:
    Domain& domain_;
    WindowsGuest& guest_;

    std::string launcher_;
    std::string target_;
    std::string args_;
    std::string directory_;

    const bool show_exit_code_;
    const bool show_console_out_;
    const bool admin_;
    const bool no_window_;
    int result_ = 0;

    uint64_t new_pid_ = 0;
    uint64_t session_id_;

    std::atomic_flag started_ = false;
    std::atomic_flag posted_message_ = false;

    std::mutex lifecycle_mtx_;
    bool launched_ = false;
    bool terminated_ = false;

    SystemCallMonitor* system_call_monitor_;
    const bool unsupported_;
};

int main(int argc, char** argv) {
    po::options_description desc("Options");
    std::string domain_name;
    std::string process_name;
    std::string target_file;
    std::string arguments;
    std::string working_directory;
    unsigned int timeout;

    // clang-format off
    desc.add_options()
      ("domain,D", po::value<std::string>(&domain_name)->required(), "The domain name or ID attach to")
      ("target,t", po::value<std::string>(&target_file)->required(), "The target file to execute in the guest")
      ("args,a", po::value<std::string>(&arguments), "Arguments to pass to the executable")
      ("console,c", "Display console output from the launched process")
      ("directory,d", po::value<std::string>(&working_directory), "Set the working directory of the launched process")
      ("exitcode,e", "Wait for the program to exit and display the exit code")
      ("nowindow,n", "Do not create a window for the new process")
      ("admin", "Run as a privileged process. Removes default value for --procname.")
      ("timeout,T", po::value<unsigned int>(&timeout)->default_value(0), "A timeout after which we exit. 0 for infinite.")
      ("procname,P", po::value<std::string>(&process_name)->default_value("explorer"), "The name of a process to hijack")
      ("syscall,S", "Monitor system calls executed by the new process")
      ("no-flush", "Don't flush the output buffer after each event")
      ("json", "Output JSON format")
      ("help", "Display program help") 
      ("unsupported", "Display system calls that we don't have handlers for (for syscalls)");
    // clang-format on

    for (auto& category : WindowsGuest::syscall_categories()) {
        desc.add_options()(category.c_str(),
                           std::string("Enable " + category + " related system calls").c_str());
    }

    // We're not mixing with printf, improve cout performance.
    std::cout.sync_with_stdio(false);

    po::variables_map vm;
    parse_program_options(argc, argv, desc, vm);

    // Get a hypervisor instance
    // This will automatically select the correct type of hypervisor.
    auto hypervisor = Hypervisor::instance();

    // Attach to the domain
    signal(SIGINT, &sig_handler);

    try {
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

        std::unique_ptr<SystemCallMonitor> syscall_monitor;
        if (vm.count("syscall")) {
            if (vm.count("exitcode") || vm.count("console")) {
                std::cerr << "Cannot use --syscall mode with --exitcode or --console\n";
                return 10;
            }
            syscall_monitor = std::make_unique<SystemCallMonitor>(
                !vm.count("no-flush"), vm.count("json"), vm.count("unsupported"));

            // Turn on system call filtering unless hooking all calls
            if (vm.count("unsupported") == 0) {
                bool category_used = false;

                if (domain->guest()->os() == OS::Windows) {
                    for (auto& category : WindowsGuest::syscall_categories()) {
                        if (vm.count(category)) {
                            auto* guest = static_cast<WindowsGuest*>(domain->guest());
                            guest->enable_category(category, domain->system_call_filter());
                            category_used = true;
                        }
                    }
                }

                if (!category_used) {
                    // Default to all supported calls
                    if (domain->guest()->os() == OS::Windows) {
                        auto* guest = static_cast<WindowsGuest*>(domain->guest());
                        guest->default_syscall_filter(domain->system_call_filter());
                    }
                }
            }
        }

        // Configure the system call filter, but don't activate it yet
        auto* guest = static_cast<WindowsGuest*>(domain->guest());
        guest->set_system_call_filter(domain->system_call_filter(),
                                      SystemCallIndex::NtTerminateProcess, true);

        // Get the session id for the target process
        uint64_t session_id = 0xFFFFFFFFFFFFFFFF;
        auto& kernel = guest->kernel();
        auto CidTable = kernel.CidTable();
        auto handles = CidTable->open_handles();
        for (auto& entry : handles) {
            try {
                if (entry->ObjectHeader()->type() == ObjectType::Process) {
                    auto process = kernel.process(entry->ObjectHeader()->Body());
                    if (boost::istarts_with(process->ImageFileName(), process_name)) {
                        // Found the target process
                        if (process->Session()) {
                            session_id = process->Session()->SessionID();
                            break;
                        }
                    }
                }
            } catch (TraceableException& ex) {
            }
        }

        if (session_id == 0xFFFFFFFFFFFFFFFF) {
            std::cerr << "Failed to find the session ID of the target process" << std::endl;
            return 20;
        }

        if (vm.count("console")) {
            guest->set_system_call_filter(domain->system_call_filter(),
                                          SystemCallIndex::NtDeviceIoControlFile, true);
        }

        // Enable system call hooking on all vcpus
        domain->intercept_system_calls(true);

        // Create a thread to terminate our monitor after a timeout
        if (timeout != 0) {
            std::thread timeout_thread(wait_for_timeout, timeout);
            timeout_thread.detach();
        }

        // Start the poll
        ExecFileTool tool(*domain, process_name, target_file, arguments, working_directory,
                          vm.count("nowindow"), vm.count("exitcode"), vm.count("console"),
                          vm.count("admin"), session_id, syscall_monitor.get(),
                          vm.count("unsupported"));

        domain->poll(tool);

        return tool.result();
    } catch (TraceableException& ex) {
        std::cerr << ex;
        return 99;
    }
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
