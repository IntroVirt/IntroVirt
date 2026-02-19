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
 * @example ivfilemon.cc
 *
 * Monitors access to a specific file path in the guest. Tracks NtOpenFile/NtCreateFile
 * opens matching the path, handles created via NtDuplicateObject, and reports all
 * operations on those handles (read, write, close, etc.). Supports normal and JSON output.
 */

#include <introvirt/introvirt.hh>

#include <boost/algorithm/string.hpp>
#include <boost/functional/hash.hpp>
#include <boost/program_options.hpp>

#include <csignal>
#include <algorithm>
#include <iostream>
#include <mutex>
#include <set>
#include <string>
#include <unordered_set>

using namespace introvirt;
using namespace introvirt::windows;
using namespace introvirt::windows::nt;

namespace po = boost::program_options;

void parse_program_options(int argc, char** argv, po::options_description& desc,
                           po::variables_map& vm);

std::unique_ptr<Domain> domain;

void sig_handler(int signum) {
    domain->interrupt();
}

static std::string normalize_path(const std::string& path) {
    std::string result = path;
    // Replace forward slashes with backslashes
    std::replace(result.begin(), result.end(), '/', '\\');
    // Lowercase for case-insensitive comparison
    boost::algorithm::to_lower(result);
    // Strip \??\ prefix for comparison
    if (result.size() >= 4 && result.substr(0, 4) == "\\??\\") {
        result = result.substr(4);
    }
    return result;
}

static bool path_matches(const std::string& user_path_normalized,
                         const nt::OBJECT_ATTRIBUTES* obj_attr, const nt::KPCR& kpcr) {
    if (obj_attr == nullptr)
        return false;
    std::string guest_path;
    try {
        guest_path = obj_attr->FullPath(kpcr);
        if (guest_path.empty())
            guest_path = obj_attr->ObjectName();
    } catch (...) {
        return false;
    }
    std::string guest_normalized = normalize_path(guest_path);
    return guest_normalized == user_path_normalized;
}

static const nt::OBJECT_ATTRIBUTES* get_object_attributes(WindowsSystemCall* handler,
                                                          SystemCallIndex index) {
    switch (index) {
    case SystemCallIndex::NtCreateFile:
        return static_cast<const NtCreateFile*>(handler)->ObjectAttributes();
    case SystemCallIndex::NtOpenFile:
        return static_cast<const NtOpenFile*>(handler)->ObjectAttributes();
    case SystemCallIndex::NtQueryAttributesFile:
        return static_cast<const NtQueryAttributesFile*>(handler)->ObjectAttributes();
    case SystemCallIndex::NtQueryFullAttributesFile:
        return static_cast<const NtQueryFullAttributesFile*>(handler)->ObjectAttributes();
    case SystemCallIndex::NtDeleteFile:
        return static_cast<const NtDeleteFile*>(handler)->ObjectAttributes();
    default:
        return nullptr;
    }
}

class FileMonitor final : public EventCallback {
public:
    FileMonitor(const std::string& target_path, bool flush, bool json)
        : target_path_normalized_(normalize_path(target_path)), flush_(flush), json_(json) {}

    void process_event(Event& event) override {
        if (event.os_type() != OS::Windows)
            return;

        auto& wevent = static_cast<WindowsEvent&>(event);

        switch (event.type()) {
        case EventType::EVENT_FAST_SYSCALL:
            handle_syscall_entry(wevent);
            break;
        case EventType::EVENT_FAST_SYSCALL_RET:
            handle_syscall_return(wevent);
            break;
        default:
            break;
        }
    }

    ~FileMonitor() { std::cout.flush(); }
private:
    using HandleKey = std::pair<uint64_t, uint64_t>;

    void handle_syscall_entry(WindowsEvent& wevent) {
        WindowsSystemCall* handler = static_cast<WindowsSystemCall*>(wevent.syscall().handler());
        if (handler == nullptr || !handler->supported())
            return;

        SystemCallIndex index = wevent.syscall().index();
        uint64_t pid = wevent.task().pid();

        switch (index) {
        case SystemCallIndex::NtCreateFile:
        case SystemCallIndex::NtOpenFile: {
            const nt::OBJECT_ATTRIBUTES* obj_attr = get_object_attributes(handler, index);
            if (path_matches(target_path_normalized_, obj_attr, wevent.task().pcr())) {
                wevent.syscall().hook_return(true);
                emit_event(wevent);
            }
            break;
        }
        case SystemCallIndex::NtQueryAttributesFile:
        case SystemCallIndex::NtQueryFullAttributesFile:
        case SystemCallIndex::NtDeleteFile: {
            const nt::OBJECT_ATTRIBUTES* obj_attr = get_object_attributes(handler, index);
            if (path_matches(target_path_normalized_, obj_attr, wevent.task().pcr())) {
                wevent.syscall().hook_return(true);
                emit_event(wevent);
            }
            break;
        }
        case SystemCallIndex::NtClose: {
            uint64_t handle = static_cast<const NtClose*>(handler)->Handle();
            std::lock_guard lock(handles_mtx_);
            if (handles_.count(HandleKey(pid, handle))) {
                handles_.erase(HandleKey(pid, handle));
                wevent.syscall().hook_return(true);
                emit_event(wevent);
            }
            break;
        }
        case SystemCallIndex::NtDuplicateObject: {
            wevent.syscall().hook_return(true);
            break;
        }
        case SystemCallIndex::NtReadFile:
        case SystemCallIndex::NtWriteFile:
        case SystemCallIndex::NtQueryInformationFile:
        case SystemCallIndex::NtSetInformationFile:
        case SystemCallIndex::NtDeviceIoControlFile: {
            uint64_t file_handle = get_file_handle(handler, index);
            std::lock_guard lock(handles_mtx_);
            if (handles_.count(HandleKey(pid, file_handle))) {
                emit_event(wevent);
            }
            break;
        }
        default:
            break;
        }
    }

    void handle_syscall_return(WindowsEvent& wevent) {
        WindowsSystemCall* handler = static_cast<WindowsSystemCall*>(wevent.syscall().handler());
        if (handler == nullptr || !handler->supported())
            return;

        const auto* nt_handler = static_cast<const nt::NtSystemCall*>(handler);
        if (!nt_handler->result().NT_SUCCESS())
            return;

        SystemCallIndex index = wevent.syscall().index();
        uint64_t pid = wevent.task().pid();

        switch (index) {
        case SystemCallIndex::NtCreateFile: {
            const nt::OBJECT_ATTRIBUTES* obj_attr = static_cast<const NtCreateFile*>(handler)->ObjectAttributes();
            if (path_matches(target_path_normalized_, obj_attr, wevent.task().pcr())) {
                uint64_t handle = static_cast<const NtCreateFile*>(handler)->FileHandle();
                std::lock_guard lock(handles_mtx_);
                handles_.insert(HandleKey(pid, handle));
                emit_event(wevent);
            }
            break;
        }
        case SystemCallIndex::NtOpenFile: {
            const nt::OBJECT_ATTRIBUTES* obj_attr =
                static_cast<const NtOpenFile*>(handler)->ObjectAttributes();
            if (path_matches(target_path_normalized_, obj_attr, wevent.task().pcr())) {
                uint64_t handle = static_cast<const NtOpenFile*>(handler)->FileHandle();
                std::lock_guard lock(handles_mtx_);
                handles_.insert(HandleKey(pid, handle));
                emit_event(wevent);
            }
            break;
        }
        case SystemCallIndex::NtDuplicateObject: {
            uint64_t src_handle = static_cast<const NtDuplicateObject*>(handler)->SourceHandle();
            uint64_t tgt_handle = static_cast<const NtDuplicateObject*>(handler)->TargetHandle();
            std::lock_guard lock(handles_mtx_);
            if (handles_.count(HandleKey(pid, src_handle))) {
                handles_.insert(HandleKey(pid, tgt_handle));
                emit_event(wevent);
            }
            break;
        }
        case SystemCallIndex::NtQueryAttributesFile:
        case SystemCallIndex::NtQueryFullAttributesFile:
        case SystemCallIndex::NtDeleteFile:
            emit_event(wevent);
            break;
        default:
            break;
        }
    }

    uint64_t get_file_handle(WindowsSystemCall* handler, SystemCallIndex index) const {
        switch (index) {
        case SystemCallIndex::NtReadFile:
        case SystemCallIndex::NtWriteFile:
            return static_cast<const NtReadWriteFile*>(handler)->FileHandle();
        case SystemCallIndex::NtQueryInformationFile:
            return static_cast<const NtQueryInformationFile*>(handler)->FileHandle();
        case SystemCallIndex::NtSetInformationFile:
            return static_cast<const NtSetInformationFile*>(handler)->FileHandle();
        case SystemCallIndex::NtDeviceIoControlFile:
            return static_cast<const NtDeviceIoControlFile*>(handler)->FileHandle();
        default:
            return 0;
        }
    }

    void emit_event(const WindowsEvent& wevent) {
        std::lock_guard lock(output_mtx_);
        if (json_) {
            std::cout << wevent.json() << '\n';
        } else {
            const Vcpu& vcpu = wevent.vcpu();
            std::cout << "Vcpu " << vcpu.id() << ": [" << wevent.task().pid() << ":"
                      << wevent.task().tid() << "] " << wevent.task().process_name() << '\n';
            std::cout << wevent.syscall().name() << '\n';
            if (wevent.syscall().handler())
                wevent.syscall().handler()->write();
        }
        if (flush_)
            std::cout.flush();
    }

    const std::string target_path_normalized_;
    const bool flush_;
    const bool json_;
    std::unordered_set<HandleKey, boost::hash<HandleKey>> handles_;
    std::mutex handles_mtx_;
    std::mutex output_mtx_;
};

int main(int argc, char** argv) {
    po::options_description desc("Options");
    std::string domain_name;
    std::string target_path;

    // clang-format off
    desc.add_options()
      ("domain,D", po::value<std::string>(&domain_name)->required(), "The domain name or ID to attach to")
      ("path,P", po::value<std::string>(&target_path)->required(), "The guest file path to monitor (e.g. C:\\path\\to\\file)")
      ("no-flush", "Don't flush the output buffer after each event")
      ("json", "Output JSON format")
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
        std::cerr << "ivfilemon only supports Windows guests\n";
        return 1;
    }

    auto* guest = static_cast<WindowsGuest*>(domain->guest());
    domain->system_call_filter().enabled(true);
    guest->set_system_call_filter(domain->system_call_filter(), SystemCallIndex::NtCreateFile, true);
    guest->set_system_call_filter(domain->system_call_filter(), SystemCallIndex::NtOpenFile, true);
    guest->set_system_call_filter(domain->system_call_filter(), SystemCallIndex::NtDeleteFile, true);
    guest->set_system_call_filter(domain->system_call_filter(), SystemCallIndex::NtQueryAttributesFile, true);
    guest->set_system_call_filter(domain->system_call_filter(), SystemCallIndex::NtQueryFullAttributesFile, true);
    guest->set_system_call_filter(domain->system_call_filter(), SystemCallIndex::NtClose, true);
    guest->set_system_call_filter(domain->system_call_filter(), SystemCallIndex::NtDuplicateObject, true);
    guest->set_system_call_filter(domain->system_call_filter(), SystemCallIndex::NtReadFile, true);
    guest->set_system_call_filter(domain->system_call_filter(), SystemCallIndex::NtWriteFile, true);
    guest->set_system_call_filter(domain->system_call_filter(), SystemCallIndex::NtQueryInformationFile, true);
    guest->set_system_call_filter(domain->system_call_filter(), SystemCallIndex::NtSetInformationFile, true);
    guest->set_system_call_filter(domain->system_call_filter(), SystemCallIndex::NtDeviceIoControlFile, true);
    domain->intercept_system_calls(true);

    FileMonitor monitor(target_path, !vm.count("no-flush"), vm.count("json"));
    domain->poll(monitor);

    return 0;
}

void parse_program_options(int argc, char** argv, po::options_description& desc, po::variables_map& vm) {
    try {
        po::store(po::parse_command_line(argc, argv, desc), vm);
        if (vm.count("help")) {
            std::cout << "ivfilemon - Monitor guest file access by path\n";
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
