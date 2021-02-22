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

#include "MEMORY_INFORMATION_IMPL.hh"

#include <introvirt/windows/kernel/nt/syscall/types/memory_information/MEMORY_BASIC_INFORMATION.hh>

namespace introvirt {
namespace windows {
namespace nt {

namespace structs {

template <typename PtrType>
struct _MEMORY_BASIC_INFORMATION {
    PtrType BaseAddress;
    PtrType AllocationBase;
    PtrType AllocationProtect; // Really is always a uint32_t, getting GCC to align right is hard
    // uint16_t PartitionId; // TODO MSDN shows this field, but not other sites. Specific versions?
    PtrType RegionSize;
    uint32_t State;
    uint32_t Protect;
    uint32_t Type;
};

static_assert(sizeof(_MEMORY_BASIC_INFORMATION<uint32_t>) == 0x1c);
static_assert(sizeof(_MEMORY_BASIC_INFORMATION<uint64_t>) == 0x30);
static_assert(offsetof(_MEMORY_BASIC_INFORMATION<uint64_t>, RegionSize) == 24);

} // namespace structs

template <typename PtrType>
using MEMORY_INFORMATION_IMPL_BASE =
    MEMORY_INFORMATION_IMPL<MEMORY_BASIC_INFORMATION, structs::_MEMORY_BASIC_INFORMATION<PtrType>>;

template <typename PtrType>
class MEMORY_BASIC_INFORMATION_IMPL final : public MEMORY_INFORMATION_IMPL_BASE<PtrType> {
  public:
    uint64_t BaseAddress() const override { return this->data_->BaseAddress; }
    uint64_t AllocationBase() const override { return this->data_->AllocationBase; }
    PAGE_PROTECTION AllocationProtect() const override { return this->data_->AllocationProtect; }
    uint64_t RegionSize() const override { return this->data_->RegionSize; }
    MEMORY_ALLOCATION_TYPE State() const override { return this->data_->State; }
    PAGE_PROTECTION Protect() const override { return this->data_->Protect; }
    MEMORY_ALLOCATION_TYPE Type() const override { return this->data_->Type; }

    void write(std::ostream& os, const std::string& linePrefix = "") const override;
    Json::Value json() const override;

    MEMORY_BASIC_INFORMATION_IMPL(const GuestVirtualAddress& gva, uint32_t buffer_size);
};

} // namespace nt
} // namespace windows
} // namespace introvirt