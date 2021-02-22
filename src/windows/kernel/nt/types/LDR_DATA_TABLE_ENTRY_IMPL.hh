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

#include "windows/kernel/nt/structs/base.hh"
#include "windows/kernel/nt/types/UNICODE_STRING_IMPL.hh"

#include <introvirt/core/memory/guest_ptr.hh>
#include <introvirt/windows/kernel/nt/types/LDR_DATA_TABLE_ENTRY.hh>

namespace introvirt {
namespace windows {
namespace nt {

namespace structs {

template <typename PtrType>
struct _LDR_DATA_TABLE_ENTRY {
    _LIST_ENTRY<PtrType> InLoadOrderLinks;
    _LIST_ENTRY<PtrType> InMemoryOrderLinks;
    _LIST_ENTRY<PtrType> InInitializationOrderLinks;
    PtrType DllBase;
    PtrType EntryPoint;
    ULONG SizeOfImage;
    _UNICODE_STRING<PtrType> FullDllName;
    _UNICODE_STRING<PtrType> BaseDllName;
};

static_assert(offsetof(_LDR_DATA_TABLE_ENTRY<uint32_t>, BaseDllName) == 0x2c);
static_assert(offsetof(_LDR_DATA_TABLE_ENTRY<uint64_t>, BaseDllName) == 0x58);

} // namespace structs

template <typename PtrType>
class NtKernelImpl;

template <typename PtrType>
class LDR_DATA_TABLE_ENTRY_IMPL final : public LDR_DATA_TABLE_ENTRY {
  public:
    /**
     * @returns The base address of this entry
     */
    GuestVirtualAddress DllBase() const override;

    /**
     * @returns The entry point of this entry
     */
    GuestVirtualAddress EntryPoint() const override;

    /**
     * @returns The size of this entry
     */
    uint32_t SizeOfImage() const override;
    void SizeOfImage(uint32_t value) override;

    /**
     * @returns The full dll name of this entry, or NULL if unavailable
     */
    std::string FullDllName() const override;
    /**
     * @returns The base dll name of this entry, or NULL if unavailable
     */
    std::string BaseDllName() const override;

    LDR_DATA_TABLE_ENTRY_IMPL(const GuestVirtualAddress& gva);

  private:
    const GuestVirtualAddress gva_;

    guest_ptr<structs::_LDR_DATA_TABLE_ENTRY<PtrType>> data_;

    mutable std::string BaseDllName_;
    mutable std::string FullDllName_;
};

} // namespace nt
} // namespace windows
} // namespace introvirt