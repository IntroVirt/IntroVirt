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
#pragma once

#include "TypeTableImpl.hh"

#include "windows/common/TypeContainer.hh"
#include "windows/kernel/ServiceDescriptorTableImpl.hh"
#include "windows/kernel/nt/structs/structs.hh"
#include "windows/kernel/nt/types/DBGKD_GET_VERSION64_IMPL.hh"
#include "windows/kernel/nt/types/KDDEBUGGER_DATA64_IMPL.hh"
#include "windows/kernel/nt/types/KPCR_IMPL.hh"
#include "windows/pe/PE_IMPL.hh"

#include <introvirt/windows/kernel/nt/NtBuildLab.hh>
#include <introvirt/windows/kernel/nt/NtKernel.hh>
#include <introvirt/windows/pe.hh>

#include <map>
#include <mutex>
#include <optional>
#include <set>
#include <unordered_map>
#include <vector>

namespace introvirt {
namespace windows {
namespace nt {

template <typename PtrType>
class NtKernelImpl final : public NtKernel, public TypeContainer {
  public:
    const DBGKD_GET_VERSION64& KdVersionBlock() const override;

    const KDDEBUGGER_DATA64& KdDebuggerDataBlock() const override;

    const ServiceDescriptorTable& KeServiceDescriptorTable() const override;

    const ServiceDescriptorTable& KeServiceDescriptorTableShadow() const override;

    bool hasObHeaderCookie() const override;

    uint8_t ObHeaderCookie() const override;

    const nt::NtBuildLab& NtBuildLab() const override;

    uint16_t NtBuildNumber() const override;

    uint16_t MajorVersion() const override;

    uint16_t MinorVersion() const override;

    unsigned int cpu_count() const override;

    bool x64() const override;

    GuestVirtualAddress symbol(const std::string& name) const override;

    GuestVirtualAddress base_address() const override;

    uint64_t InvalidPteMask() const override;

    const TypeTable& types() const override;

    const pe::PE& pe() const override;

    const mspdb::PDB& pdb() const override;

    std::shared_ptr<OBJECT_DIRECTORY> RootDirectoryObject() const override;

    std::unique_ptr<HANDLE_TABLE> CidTable() override;

    std::unique_ptr<const HANDLE_TABLE> CidTable() const override;

    std::vector<std::shared_ptr<const LDR_DATA_TABLE_ENTRY>> PsLoadedModuleList() const override;

    std::string get_device_drive_letter(const nt::DEVICE_OBJECT& device) const override;

    KPCR& kpcr(const Vcpu& vcpu) override;

    const KPCR& kpcr(const Vcpu& vcpu) const override;

    const WindowsGuest& guest() const override;

    std::shared_ptr<THREAD> thread(const GuestVirtualAddress& address) const override HOT;

    std::shared_ptr<PROCESS> process(const GuestVirtualAddress& address) const override HOT;

    /**
     * @brief Get the path to the profile directory for this kernel
     *
     * @return std::string
     */
    std::string profile_path() const override;

    NtKernelImpl(WindowsGuest& guest);
    ~NtKernelImpl() override;

  private:
    static constexpr bool is64Bit() { return sizeof(PtrType) == sizeof(uint64_t); }

    void reparse_drive_letters();

    std::optional<TypeTableImpl<PtrType>> type_table_;

    GuestVirtualAddress base_address_;
    GuestVirtualAddress global_directory_address_;

    std::optional<pe::PE_IMPL> pe_;
    std::optional<nt::DBGKD_GET_VERSION64_IMPL> KdVersionBlock_;
    std::optional<nt::KDDEBUGGER_DATA64_IMPL<PtrType>> KdDebuggerDataBlock_;
    std::optional<nt::NtBuildLab> NtBuildLab_;

    std::optional<ServiceDescriptorTableImpl<PtrType>> KeServiceDescriptorTable_;
    std::optional<ServiceDescriptorTableImpl<PtrType>> KeServiceDescriptorTableShadow_;

    std::vector<KPCR_IMPL<PtrType>> kpcrs_;
    std::map<std::string, GuestVirtualAddress> drive_letters_;
    mutable std::mutex drive_letters_mtx_;

    const WindowsGuest& guest_;

    unsigned int cpu_count_ = 0;
    uint64_t NtBuildNumber_;
    uint64_t InvalidPteMask_ = 0;
    uint16_t MajorVersion_;
    uint16_t MinorVersion_;
    uint8_t ObHeaderCookie_ = 0;
    bool hasObHeaderCookie_ = false;

    struct {
        mutable std::mutex mtx_;
        mutable std::unordered_map<uint64_t, std::pair<uint64_t, std::shared_ptr<nt::PROCESS>>>
            map_;
    } procs_;

    struct {
        mutable std::mutex mtx_;
        mutable std::unordered_map<uint64_t, std::pair<uint64_t, std::shared_ptr<nt::THREAD>>> map_;
    } threads_;
};

} // namespace nt
} // namespace windows
} // namespace introvirt