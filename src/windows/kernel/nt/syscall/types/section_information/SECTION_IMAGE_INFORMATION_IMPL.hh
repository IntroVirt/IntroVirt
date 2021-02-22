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

#include <introvirt/windows/kernel/nt/syscall/types/section_information/SECTION_IMAGE_INFORMATION.hh>

namespace introvirt {
namespace windows {
namespace nt {

namespace structs {

template <typename PtrType>
struct _SECTION_IMAGE_INFORMATION {
    PtrType TransferAddress;
    uint32_t ZeroBits;
    PtrType MaximumStackSize;
    PtrType CommittedStackSize;
    uint32_t SubSystemType;
};

} // namespace structs

template <typename PtrType>
using SECTION_IMAGE_INFORMATION_IMPL_BASE =
    SECTION_INFORMATION_IMPL<SECTION_IMAGE_INFORMATION,
                             structs::_SECTION_IMAGE_INFORMATION<PtrType>>;

template <typename PtrType>
class SECTION_IMAGE_INFORMATION_IMPL final : public SECTION_IMAGE_INFORMATION_IMPL_BASE<PtrType> {
  public:
    uint64_t TransferAddress() const override { return this->data_->TransferAddress; }
    void TransferAddress(uint64_t value) override { this->data_->TransferAddress = value; }

    uint32_t ZeroBits() const override { return this->data_->ZeroBits; }
    void ZeroBits(uint32_t value) override { this->data_->ZeroBits = value; }

    uint64_t MaximumStackSize() const override { return this->data_->MaximumStackSize; }
    void MaximumStackSize(uint64_t value) override { this->data_->MaximumStackSize = value; }

    uint64_t CommittedStackSize() const override { return this->data_->CommittedStackSize; }
    void CommittedStackSize(uint64_t value) override { this->data_->CommittedStackSize = value; }

    uint32_t SubSystemType() const override { return this->data_->SubSystemType; }
    void SubSystemType(uint32_t value) override { this->data_->SubSystemType = value; }

    void write(std::ostream& os, const std::string& linePrefix = "") const override;
    Json::Value json() const override;

    SECTION_IMAGE_INFORMATION_IMPL(const GuestVirtualAddress& gva, uint32_t buffer_size)
        : SECTION_IMAGE_INFORMATION_IMPL_BASE<PtrType>(
              SECTION_INFORMATION_CLASS::SectionImageInformation, gva, buffer_size) {}
};

} // namespace nt
} // namespace windows
} // namespace introvirt