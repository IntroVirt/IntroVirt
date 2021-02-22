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

#include "CONTROL_AREA_IMPL.hh"
#include "windows/kernel/nt/structs/structs.hh"

#include <introvirt/windows/kernel/nt/types/MMVAD.hh>

#include <mutex>
#include <optional>

namespace introvirt {
namespace windows {
namespace nt {

template <typename PtrType>
class NtKernelImpl;

template <typename PtrType>
class MMVAD_IMPL final : public MMVAD, public std::enable_shared_from_this<MMVAD_IMPL<PtrType>> {
  public:
    /** @returns The four-byte pool tag before the structure */
    std::string tag() const override;

    /** @returns The type of structure being used by this MMVAD */
    VadStructure structure() const override;

    uint64_t CommitCharge() const override;

    /** @returns The starting page number. */
    uint64_t StartingVpn() const override;
    /** @returns The last page number in the region. */
    uint64_t EndingVpn() const override;
    /** @returns The the backing FILE_OBJECT, if VadType is PhysicalFileMapped. Otherwise NULL. */
    const FILE_OBJECT* FileObject() const override;
    /** @returns The left MMVAD child or null. */
    std::shared_ptr<const MMVAD> LeftChild() const override;
    /** @returns The right MMVAD child or null. */
    std::shared_ptr<const MMVAD> RightChild() const override;
    /** @returns The parent MMVAD or null. */
    std::shared_ptr<const MMVAD> Parent() const override;
    /** @returns The region type. */
    VadType Type() const override;
    /** @returns The protection of the region. */
    PAGE_PROTECTION Protection() const override;
    /** @returns The allocation type of the region. */
    const MEMORY_ALLOCATION_TYPE& Allocation() const override;
    /** @returns True if the memory is considered private */
    bool Private() const override;

    /** @returns The size, in bytes, of the region. */
    uint64_t RegionSize() const override;

    /** @returns The starting address of the region (equivalent to StartingVpn() << 12). */
    GuestVirtualAddress StartingAddress() const override;

    /** @returns The last address of the region [((EndingVpn() + 1) << 12) - 1]; */
    GuestVirtualAddress EndingAddress() const override;

    GuestVirtualAddress address() const override;

    std::vector<std::shared_ptr<const MMVAD>> VadTreeInOrder() const override;

    GuestVirtualAddress FirstPrototypePte() const override;
    GuestVirtualAddress LastContiguousPte() const override;

    bool locked() const override;

    /**
     * @brief Search for the MMVAD entry for the given address in children
     *
     * @param VirtualAddress The address to search for
     * @returns The matching MMVAD entry, or nullptr.
     */
    std::shared_ptr<const MMVAD> search(const GuestVirtualAddress& gva) const override;

    MMVAD_IMPL(const NtKernelImpl<PtrType>& kernel, const GuestVirtualAddress& gva);

  private:
    GuestVirtualAddress ControlAreaPtr() const;
    const CONTROL_AREA* ControlArea() const;
    bool MemCommit() const;
    GuestVirtualAddress LeftChildPtr() const;
    GuestVirtualAddress RightChildPtr() const;
    std::shared_ptr<const MMVAD> search(const GuestVirtualAddress& gva,
                                        std::set<uint64_t>& seen) const;

  private:
    const NtKernelImpl<PtrType>& kernel_;
    const GuestVirtualAddress gva_;

    const structs::MMVAD_SHORT* mmvad_short_;
    const structs::MMVAD* mmvad_;
    const structs::SUBSECTION* subsection_;

    mutable guest_ptr<char[]> buffer_;

    MMVAD::VadType type_{MMVAD::VadNone};
    MEMORY_ALLOCATION_TYPE Allocation_;

    mutable std::optional<CONTROL_AREA_IMPL<PtrType>> control_area_;
    mutable std::recursive_mutex mtx_;
};

} // namespace nt
} // namespace windows
} // namespace introvirt