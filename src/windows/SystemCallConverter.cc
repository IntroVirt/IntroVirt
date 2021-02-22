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
#include <introvirt/core/exception/GuestDetectionException.hh>
#include <introvirt/windows/WindowsGuest.hh>
#include <introvirt/windows/kernel/ServiceDescriptorTable.hh>
#include <introvirt/windows/kernel/SystemCallConverter.hh>
#include <introvirt/windows/kernel/nt/NtKernel.hh>
#include <introvirt/windows/kernel/nt/const/ObjectType.hh>
#include <introvirt/windows/kernel/nt/types/HANDLE_TABLE.hh>
#include <introvirt/windows/kernel/nt/types/HANDLE_TABLE_ENTRY.hh>
#include <introvirt/windows/kernel/nt/types/objects/OBJECT_HEADER.hh>
#include <introvirt/windows/kernel/nt/types/objects/PROCESS.hh>

#include <introvirt/windows/pe.hh>

#include <introvirt/core/domain/Vcpu.hh>
#include <introvirt/core/memory/GuestVirtualAddress.hh>
#include <introvirt/util/compiler.hh>
#include <introvirt/util/json/json.hh>

#include <log4cxx/logger.h>
#include <mspdb/pdb_exception.hh>

#include <fstream>

namespace introvirt {
namespace windows {

static log4cxx::LoggerPtr
    logger(log4cxx::Logger::getLogger("introvirt.windows.kernel.SystemCallConverter"));

SystemCallIndex SystemCallConverter::normalize(uint32_t index) const {
    index &= SystemCallIndexMask;

    if ((index & 0x1000) != 0) {
        // Win32k
        return _normalize(index & 0xFFF, to_normalized_win32k_);
    } else {
        // Nt
        return _normalize(index & 0xFFF, to_normalized_nt_);
    }
}

SystemCallIndex
SystemCallConverter::_normalize(uint32_t index,
                                const std::vector<SystemCallIndex>& to_normalized) const {

    if (unlikely(index > to_normalized.size())) {
        return SystemCallIndex::UNKNOWN_SYSTEM_CALL;
    }
    return to_normalized[index];
}

uint32_t SystemCallConverter::native(SystemCallIndex index) const {
    auto iter = to_native_.find(index);
    if (unlikely(iter == to_native_.end())) {
        return 0xFFFFFFFF;
    }
    return iter->second;
}

uint32_t SystemCallConverter::count() const { return to_native_.size(); }

static bool parse_service_table(const ServiceTable& table, const GuestVirtualAddress& base_address,
                                const mspdb::PDB& pdb, std::vector<SystemCallIndex>& to_normalized,
                                std::unordered_map<SystemCallIndex, uint32_t>& to_native,
                                uint32_t offset) {

    bool added_new = false;

    to_normalized.resize(table.length(), SystemCallIndex::UNKNOWN_SYSTEM_CALL);

    // Walk over the calls
    for (uint32_t i = 0; i < table.length(); ++i) {
        // Get the function the table entry points to
        const auto address = table.entry(i);

        // Look it up in the PDB
        const mspdb::Symbol* symbol;
        symbol = pdb.rva_to_symbol(address - base_address);
        if (!symbol)
            continue;

        // Try to determine which call it is
        const SystemCallIndex index = system_call_from_string(symbol->name());
        if (index == SystemCallIndex::UNKNOWN_SYSTEM_CALL) {
            LOG4CXX_DEBUG(logger,
                          "Unknown system call index " << i << ": '" << symbol->name() << "'");
            continue;
        }

        // Add it to the table
        if (to_normalized[i] == SystemCallIndex::UNKNOWN_SYSTEM_CALL) {
            to_normalized[i] = index;
            to_native[index] = i + offset;
            added_new = true;
        }
    }

    return added_new;
}

static constexpr unsigned int JsonVersion = 1;

// Return true if the load was complete, false if we should try to look for more calls in the guest
static void load_from_json(const nt::NtKernel& kernel,
                           std::vector<SystemCallIndex>& to_normalized_nt,
                           std::vector<SystemCallIndex>& to_normalized_win32k,
                           std::unordered_map<SystemCallIndex, uint32_t>& to_native) {

    std::ifstream file(kernel.profile_path() + "/syscall.json", std::ifstream::binary);
    if (!file.good()) {
        LOG4CXX_DEBUG(logger, "Failed to open system call profile in " << kernel.profile_path());
        return;
    }

    // Parse it
    Json::Value root;
    file >> root;

    if (!root.isMember("version"))
        return;
    if (root["version"].asUInt() != JsonVersion)
        return;

    if (root.isMember("nt")) {
        Json::Value nt = root["nt"];
        const uint32_t max = nt["max"].asUInt();
        to_normalized_nt.resize(max, SystemCallIndex::UNKNOWN_SYSTEM_CALL);

        Json::Value calls = nt["calls"];
        for (auto iter = calls.begin(); iter != calls.end(); ++iter) {
            const uint32_t raw_index = std::stoi(iter.key().asString());
            const SystemCallIndex normalized = system_call_from_string((*iter).asString());
            if (normalized != SystemCallIndex::UNKNOWN_SYSTEM_CALL) {
                to_normalized_nt[raw_index] = normalized;
                to_native[normalized] = raw_index;
            } else {
                LOG4CXX_INFO(logger, "Json has unknown system call: " << iter.key().asString());
            }
        }
    }

    if (root.isMember("win32k")) {
        Json::Value win32k = root["win32k"];
        const uint32_t max = win32k["max"].asUInt();
        to_normalized_win32k.resize(max & 0xFFF, SystemCallIndex::UNKNOWN_SYSTEM_CALL);

        Json::Value calls = win32k["calls"];
        for (auto iter = calls.begin(); iter != calls.end(); ++iter) {
            const uint32_t raw_index = std::stoi(iter.key().asString());
            const SystemCallIndex normalized = system_call_from_string((*iter).asString());
            if (normalized != SystemCallIndex::UNKNOWN_SYSTEM_CALL) {
                to_normalized_win32k[raw_index & 0xFFF] = normalized;
                to_native[normalized] = raw_index;
            } else {
                LOG4CXX_INFO(logger, "Json has unknown system call: " << iter.key().asString());
            }
        }
    }

    LOG4CXX_DEBUG(logger, "Loaded " << kernel.profile_path() + "/syscall.json");
}

static void save_to_json(const nt::NtKernel& kernel, std::vector<SystemCallIndex>& to_normalized_nt,
                         std::vector<SystemCallIndex>& to_normalized_win32k) {

    std::ofstream file(kernel.profile_path() + "/syscall.json",
                       std::ofstream::binary | std::ofstream::trunc);

    if (!file.good()) {
        LOG4CXX_WARN(logger, "Failed to save " << kernel.profile_path() + "/syscall.json");
        return;
    }

    Json::Value root;
    root["version"] = JsonVersion;

    Json::Value nt;
    Json::Value nt_calls;
    for (unsigned int i = 0; i < to_normalized_nt.size(); ++i) {
        SystemCallIndex normalized = to_normalized_nt[i];
        if (normalized != SystemCallIndex::UNKNOWN_SYSTEM_CALL) {
            nt_calls[std::to_string(i)] = to_string(normalized);
        }
    }
    nt["max"] = to_normalized_nt.size();
    nt["calls"] = std::move(nt_calls);
    root["nt"] = std::move(nt);

    Json::Value win32k;
    Json::Value win32k_calls;
    for (unsigned int i = 0; i < to_normalized_win32k.size(); ++i) {
        SystemCallIndex normalized = to_normalized_win32k[i];
        if (normalized != SystemCallIndex::UNKNOWN_SYSTEM_CALL) {
            win32k_calls[std::to_string(i | 0x1000)] = to_string(normalized);
        }
    }
    win32k["max"] = to_normalized_win32k.size();
    win32k["calls"] = std::move(win32k_calls);
    root["win32k"] = std::move(win32k);

    file << root;
    LOG4CXX_DEBUG(logger, "Saved " << kernel.profile_path() + "/syscall.json");
}

SystemCallConverter::SystemCallConverter(const WindowsGuest& guest) {
    // Get the Service Descriptor Table
    const auto& kernel = guest.kernel();
    const auto& pdb = kernel.pdb();
    const auto& ssdt = kernel.KeServiceDescriptorTableShadow();

    if (ssdt.count() < 2) {
        throw GuestDetectionException(guest.domain(), "Failed to find proper SSDT");
    }

    const auto& nt_calls = ssdt.entry(0).service_table();
    const auto& win32k_calls = ssdt.entry(1).service_table();

    load_from_json(kernel, to_normalized_nt_, to_normalized_win32k_, to_native_);

    to_normalized_nt_.resize(nt_calls.length(), SystemCallIndex::UNKNOWN_SYSTEM_CALL);
    to_normalized_win32k_.resize(win32k_calls.length(), SystemCallIndex::UNKNOWN_SYSTEM_CALL);

    //
    // Find Nt system calls
    //
    bool save_json;
    save_json =
        parse_service_table(nt_calls, kernel.base_address(), pdb, to_normalized_nt_, to_native_, 0);

    LOG4CXX_DEBUG(logger, "Detected " << to_normalized_nt_.size() << " NT system calls");
    if (to_normalized_nt_.empty())
        throw GuestDetectionException(guest.domain(), "Failed to find NT system call numbers");

    //
    // Now find Win32k system calls
    //

    // First get the address of the win32k module
    GuestVirtualAddress pWin32k;
    for (auto& module : kernel.PsLoadedModuleList()) {
        if (module->BaseDllName() == "win32k.sys") {
            pWin32k = module->DllBase();
            break;
        }
    }

    if (unlikely(!pWin32k)) {
        throw GuestDetectionException(guest.domain(), "Failed to find Win32k kernel module");
    }

    /*
     * Find a process that has win32k mapped in
     * Not all of them do, and if we're not in the right
     * address space, then the PE parsing won't work.
     */
    auto CidTable = kernel.CidTable();
    for (auto& entry : CidTable->open_handles()) {
        std::unique_ptr<nt::OBJECT_HEADER> header(entry->ObjectHeader());
        if (header->type() == nt::ObjectType::Process) {
            auto process = kernel.process(header->Body());
            if (process->Win32Process()) {
                try {
                    pWin32k.page_directory(process->DirectoryTableBase());
                    auto win32k = pe::PE::make_unique(pWin32k);
                    save_json |= parse_service_table(win32k_calls, pWin32k, win32k->pdb(),
                                                     to_normalized_win32k_, to_native_, 0x1000);

                    break;
                } catch (TraceableException& ex) {
                }
            }
        }
    }

    LOG4CXX_DEBUG(logger, "Detected " << to_normalized_win32k_.size() << " Win32k system calls");
    if (to_normalized_win32k_.empty())
        throw GuestDetectionException(guest.domain(), "Failed to find Win32k system call numbers");

    if (save_json)
        save_to_json(kernel, to_normalized_nt_, to_normalized_win32k_);
}

SystemCallConverter::~SystemCallConverter() = default;

} // namespace windows
} // namespace introvirt