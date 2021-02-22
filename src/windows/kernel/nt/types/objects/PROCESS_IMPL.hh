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

#include "DISPATCHER_OBJECT_IMPL.hh"
#include "TOKEN_IMPL.hh"
#include "windows/kernel/nt/structs/structs.hh"
#include "windows/kernel/nt/types/MM_SESSION_SPACE_IMPL.hh"
#include "windows/kernel/nt/types/PEB_IMPL.hh"

#include <introvirt/core/memory/guest_ptr.hh>
#include <introvirt/fwd.hh>
#include <introvirt/windows/kernel/nt/types/MMVAD.hh>
#include <introvirt/windows/kernel/nt/types/MM_SESSION_SPACE.hh>
#include <introvirt/windows/kernel/nt/types/PEB.hh>
#include <introvirt/windows/kernel/nt/types/objects/PROCESS.hh>

#include <memory>

namespace introvirt {
namespace windows {
namespace nt {

template <typename PtrType>
class PROCESS_IMPL final : public DISPATCHER_OBJECT_IMPL<PtrType, PROCESS> {
  public:
    const PEB* Peb() const override;
    PEB* Peb() override;

    const PEB* WoW64Process() const override;
    PEB* WoW64Process() override;

    const std::string& ImageFileName() const override;
    void ImageFileName(const std::string& value) override;

    const std::string& full_path() const override;

    std::unique_ptr<HANDLE_TABLE> ObjectTable() override;
    std::unique_ptr<const HANDLE_TABLE> ObjectTable() const override;

    uint64_t UniqueProcessId() const override;

    uint64_t InheritedFromUniqueProcessId() const override;
    void InheritedFromUniqueProcessId(uint64_t pid) override;

    std::shared_ptr<const MMVAD> VadRoot() const override;

    TOKEN& Token() override;
    const TOKEN& Token() const override;

    uint64_t DirectoryTableBase() const override;

    uint64_t UserDirectoryTableBase() const override;

    uint32_t Cookie() const override;

    uint64_t SectionBaseAddress() const override;

    std::vector<std::shared_ptr<THREAD>> ThreadList() override;
    std::vector<std::shared_ptr<const THREAD>> ThreadList() const override;

    const MM_SESSION_SPACE* Session() const override;

    bool isWow64Process() const override;

    bool DisableDynamicCode() const override;

    void DisableDynamicCode(bool DisableDynamicCode) override;

    bool DisableDynamicCodeAllowOptOut() const override;
    void DisableDynamicCodeAllowOptOut(bool DisableDynamicCodeAllowOptOut) override;

    uint32_t ModifiedPageCount() const override;
    void ModifiedPageCount(uint32_t ModifiedPageCount) override;

    WindowsTime CreateTime() const override;
    void CreateTime(const WindowsTime& time) override;

    uint64_t MinimumWorkingSetSize() const override;
    void MinimumWorkingSetSize(uint64_t MinimumWorkingSetSize) override;

    uint64_t MaximumWorkingSetSize() const override;
    void MaximumWorkingSetSize(uint64_t MaximumWorkingSetSize) override;

    uint8_t ProtectionLevel() const override;
    void ProtectionLevel(uint8_t Level) override;

    GuestVirtualAddress Win32Process() const override;

    PROCESS_IMPL(const NtKernelImpl<PtrType>& kernel, const GuestVirtualAddress& gva);
    PROCESS_IMPL(const NtKernelImpl<PtrType>& kernel,
                 std::unique_ptr<OBJECT_HEADER_IMPL<PtrType>>&& object_header);

  private:
    void init(const NtKernelImpl<PtrType>& kernel, const GuestVirtualAddress& gva);

    uint64_t VadRootNodeAddress() const;

  private:
    const NtKernelImpl<PtrType>& kernel_;

    const structs::EPROCESS* eprocess_;
    const structs::ETHREAD* ethread_;
    guest_ptr<char[]> buffer_;

    mutable std::mutex mtx_;

    mutable std::optional<PEB_IMPL<PtrType>> peb_;
    mutable std::optional<PEB_IMPL<uint32_t>> WoW64Process_;
    mutable std::optional<TOKEN_IMPL<PtrType>> token_;
    mutable std::optional<MM_SESSION_SPACE_IMPL<PtrType>> session_;
    mutable std::string ImageFileName_;

    mutable std::mutex full_path_mtx_;
    mutable std::string full_path_;
};

} // namespace nt
} // namespace windows
} // namespace introvirt