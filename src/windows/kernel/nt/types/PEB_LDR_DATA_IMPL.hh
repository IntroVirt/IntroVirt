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
#include "windows/kernel/nt/structs/structs.hh"

#include <introvirt/core/memory/guest_ptr.hh>
#include <introvirt/windows/kernel/nt/types/PEB_LDR_DATA.hh>

namespace introvirt {
namespace windows {
namespace nt {

namespace structs {

template <typename PtrType>
struct _PEB_LDR_DATA {
    uint32_t Length;
    uint8_t Initialized;
    PtrType SsHandle;
    _LIST_ENTRY<PtrType> InLoadOrderModuleList;
    _LIST_ENTRY<PtrType> InMemoryOrderModuleList;
    _LIST_ENTRY<PtrType> InInitializationOrderModuleList;
    PtrType EntryInProgress;
} __attribute__((__aligned__(sizeof(PtrType)), __ms_struct__));

static_assert(offsetof(_PEB_LDR_DATA<uint32_t>, InLoadOrderModuleList) == 0xc);
static_assert(offsetof(_PEB_LDR_DATA<uint64_t>, InLoadOrderModuleList) == 0x10);

static_assert(offsetof(_PEB_LDR_DATA<uint32_t>, EntryInProgress) == 0x24);
static_assert(offsetof(_PEB_LDR_DATA<uint64_t>, EntryInProgress) == 0x40);

} // namespace structs

template <typename PtrType>
class NtKernelImpl;

// TODO(papes): Probably make an interable class instead of using vector

template <typename PtrType>
class PEB_LDR_DATA_IMPL final : public PEB_LDR_DATA {
  public:
    const std::vector<std::shared_ptr<const LDR_DATA_TABLE_ENTRY>>&
    InLoadOrderList() const override {
        return InLoadOrderList_;
    }

    PEB_LDR_DATA_IMPL(const GuestVirtualAddress& gva);

  private:
    const GuestVirtualAddress gva_;

    guest_ptr<structs::_PEB_LDR_DATA<PtrType>> data_;

    std::vector<std::shared_ptr<const LDR_DATA_TABLE_ENTRY>> InLoadOrderList_;
};

} // namespace nt
} // namespace windows
} // namespace introvirt