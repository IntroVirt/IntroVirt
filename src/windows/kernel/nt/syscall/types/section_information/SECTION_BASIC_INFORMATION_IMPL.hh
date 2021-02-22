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

#include "SECTION_INFORMATION_IMPL.hh"

#include <introvirt/windows/kernel/nt/syscall/types/section_information/SECTION_BASIC_INFORMATION.hh>

namespace introvirt {
namespace windows {
namespace nt {

namespace structs {

template <typename PtrType>
struct _SECTION_BASIC_INFORMATION {
    PtrType BaseAddress;
    uint32_t AllocationAttributes;
    uint64_t MaximumSize;
};

} // namespace structs

template <typename PtrType>
using SECTION_BASIC_INFORMATION_IMPL_BASE =
    SECTION_INFORMATION_IMPL<SECTION_BASIC_INFORMATION,
                             structs::_SECTION_BASIC_INFORMATION<PtrType>>;

template <typename PtrType>
class SECTION_BASIC_INFORMATION_IMPL final : public SECTION_BASIC_INFORMATION_IMPL_BASE<PtrType> {
  public:
    uint64_t BaseAddress() const override { return this->data_->BaseAddress; }
    void BaseAddress(uint64_t value) override { this->data_->BaseAddress = value; }

    uint32_t AllocationAttributes() const override { return this->data_->AllocationAttributes; }
    void AllocationAttributes(uint32_t value) override {
        this->data_->AllocationAttributes = value;
    }

    uint64_t MaximumSize() const override { return this->data_->MaximumSize; }
    void MaximumSize(uint64_t value) override { this->data_->MaximumSize = value; }

    void write(std::ostream& os, const std::string& linePrefix = "") const override;
    Json::Value json() const override;

    SECTION_BASIC_INFORMATION_IMPL(const GuestVirtualAddress& gva, uint32_t buffer_size)
        : SECTION_BASIC_INFORMATION_IMPL_BASE<PtrType>(
              SECTION_INFORMATION_CLASS::SectionBasicInformation, gva, buffer_size) {}
};

} // namespace nt
} // namespace windows
} // namespace introvirt