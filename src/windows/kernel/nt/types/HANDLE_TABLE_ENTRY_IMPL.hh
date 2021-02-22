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

#include "windows/kernel/nt/structs/structs.hh"

#include <introvirt/core/memory/guest_ptr.hh>
#include <introvirt/windows/kernel/nt/types/HANDLE_TABLE_ENTRY.hh>

namespace introvirt {
namespace windows {
namespace nt {

template <typename PtrType>
class NtKernelImpl;

template <typename PtrType>
class HANDLE_TABLE_ENTRY_IMPL final : public HANDLE_TABLE_ENTRY {
  public:
    /** @returns The value of the entry */
    uint64_t Value() const override;

    /** @returns The OBJECT_HEADER for this handle */
    std::unique_ptr<OBJECT_HEADER> ObjectHeader() const override;

    /** @returns The access level granted to the object through this handle. */
    ACCESS_MASK GrantedAccess() const override;

    /** Set the granted access mask after the handle is created. */
    void GrantedAccess(const ACCESS_MASK& mask) override;

    /** @returns The handle number. */
    uint64_t Handle() const override;

    /**
     * @brief Get the address of the structure
     */
    GuestVirtualAddress address() const override;

    /**
     * @param vcpu The vcpu to use as context
     * @param wincfg The wincfg object for guest information
     * @param virtual_address address of the table entry
     * @param handle The handle number being parsed.
     * @param isPspCidTable True if the handle entry points directly to the object, rather than to
     * the OBJECT_HEADER
     */
    HANDLE_TABLE_ENTRY_IMPL(const NtKernelImpl<PtrType>& kernel, const GuestVirtualAddress& gva,
                            uint64_t handle, bool isPspCidTable);

    ~HANDLE_TABLE_ENTRY_IMPL() override;

  private:
    const NtKernelImpl<PtrType>& kernel_;
    const GuestVirtualAddress gva_;
    const uint64_t handle;
    const bool isPspCidTable;
    const structs::HANDLE_TABLE_ENTRY* offsets_;

    guest_ptr<char[]> buffer_;
};

} // namespace nt
} // namespace windows
} // namespace introvirt