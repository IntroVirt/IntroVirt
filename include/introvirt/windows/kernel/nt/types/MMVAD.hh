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

#include <introvirt/core/memory/GuestVirtualAddress.hh>
#include <introvirt/windows/kernel/nt/const/MEMORY_ALLOCATION_TYPE.hh>
#include <introvirt/windows/kernel/nt/const/PAGE_PROTECTION.hh>
#include <introvirt/windows/kernel/nt/fwd.hh>

#include <cstdint>
#include <memory>
#include <string>
#include <vector>

namespace introvirt {
namespace windows {
namespace nt {

/**
 * The VaD type can be one of these structures internally
 */
enum class VadStructure {
    MMVAD_SHORT,
    MMVAD,

    UNKNOWN
};

/**
 * @brief An entry inside a process's VAD table.
 *
 * All pages with an MMVAD instance are guaranteed to have the same page
 * protection, type, and point to the same mapped file (if applicable).
 */
class MMVAD {
  public:
    enum VadType {
        VadNone = 0,
        VadDevicePhysicalMemory,
        VadImageMap,
        VadAwe,
        VadWriteWatch,
        VadLargePages,
        VadRotatePhysical,
        VadLargePageSection
    };

    /** @returns The four-byte pool tag before the structure */
    virtual std::string tag() const = 0;

    /** @returns The type of structure being used by this MMVAD */
    virtual VadStructure structure() const = 0;

    virtual uint64_t CommitCharge() const = 0;

    /** @returns The starting page number. */
    virtual uint64_t StartingVpn() const = 0;
    /** @returns The last page number in the region. */
    virtual uint64_t EndingVpn() const = 0;
    /** @returns The the backing FILE_OBJECT, if VadType is PhysicalFileMapped. Otherwise NULL. */
    virtual const FILE_OBJECT* FileObject() const = 0;
    /** @returns The left MMVAD child or null. */
    virtual std::shared_ptr<const MMVAD> LeftChild() const = 0;
    /** @returns The right MMVAD child or null. */
    virtual std::shared_ptr<const MMVAD> RightChild() const = 0;
    /** @returns The parent MMVAD or null. */
    virtual std::shared_ptr<const MMVAD> Parent() const = 0;
    /** @returns The region type. */
    virtual VadType Type() const = 0;
    /** @returns The protection of the region. */
    virtual PAGE_PROTECTION Protection() const = 0;
    /** @returns The allocation type of the region. */
    virtual const MEMORY_ALLOCATION_TYPE& Allocation() const = 0;
    /** @returns True if the memory is considered private */
    virtual bool Private() const = 0;

    /** @returns The size, in bytes, of the region. */
    virtual uint64_t RegionSize() const = 0;

    /** @returns The starting address of the region (equivalent to StartingVpn() << 12). */
    virtual GuestVirtualAddress StartingAddress() const = 0;

    /** @returns The last address of the region [((EndingVpn() + 1) << 12) - 1]; */
    virtual GuestVirtualAddress EndingAddress() const = 0;

    virtual GuestVirtualAddress address() const = 0;

    virtual bool locked() const = 0;

    virtual std::vector<std::shared_ptr<const MMVAD>> VadTreeInOrder() const = 0;

    virtual GuestVirtualAddress FirstPrototypePte() const = 0;
    virtual GuestVirtualAddress LastContiguousPte() const = 0;

    /**
     * @brief Search for the MMVAD entry for the given address in children
     *
     * @param VirtualAddress The address to search for
     * @returns The matching MMVAD entry, or nullptr.
     */
    virtual std::shared_ptr<const MMVAD> search(const GuestVirtualAddress& gva) const = 0;

    virtual ~MMVAD() = default;
};

/**
 * @brief Get the VadType as a string
 */
const std::string& to_string(MMVAD::VadType);

/**
 * @brief Stream operator overload for VadType
 */
std::ostream& operator<<(std::ostream&, MMVAD::VadType);

/**
 * @brief Get the VadType as a string
 */
const std::string& to_string(VadStructure);

/**
 * @brief Stream operator overload for VadType
 */
std::ostream& operator<<(std::ostream&, VadStructure);

} // namespace nt
} // namespace windows
} // namespace introvirt
