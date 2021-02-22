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

#include <introvirt/windows/kernel/nt/syscall/types/section_information/SECTION_RELOCATION_INFORMATION.hh>

namespace introvirt {
namespace windows {
namespace nt {

namespace structs {

template <typename PtrType>
struct _SECTION_RELOCATION_INFORMATION {
    PtrType BaseAddress;
};

} // namespace structs

template <typename PtrType>
using SECTION_RELOCATION_INFORMATION_IMPL_BASE =
    SECTION_INFORMATION_IMPL<SECTION_RELOCATION_INFORMATION,
                             structs::_SECTION_RELOCATION_INFORMATION<PtrType>>;

template <typename PtrType>
class SECTION_RELOCATION_INFORMATION_IMPL final
    : public SECTION_RELOCATION_INFORMATION_IMPL_BASE<PtrType> {
  public:
    uint64_t BaseAddress() const override { return this->data_->BaseAddress; }
    void BaseAddress(uint64_t value) override { this->data_->BaseAddress = value; }

    void write(std::ostream& os, const std::string& linePrefix = "") const override;
    Json::Value json() const override;

    SECTION_RELOCATION_INFORMATION_IMPL(const GuestVirtualAddress& gva, uint32_t buffer_size)
        : SECTION_RELOCATION_INFORMATION_IMPL_BASE<PtrType>(
              SECTION_INFORMATION_CLASS::SectionRelocationInformation, gva, buffer_size) {}
};

} // namespace nt
} // namespace windows
} // namespace introvirt