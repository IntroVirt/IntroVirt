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

#include "MEMORY_INFORMATION_IMPL.hh"
#include "windows/kernel/nt/types/UNICODE_STRING_IMPL.hh"

#include <introvirt/windows/common/WStr.hh>
#include <introvirt/windows/kernel/nt/syscall/types/memory_information/MEMORY_SECTION_NAME.hh>

#include <optional>

namespace introvirt {
namespace windows {
namespace nt {

namespace structs {

template <typename PtrType>
struct _MEMORY_SECTION_NAME {
    _UNICODE_STRING<PtrType> SectionFileName;
    uint16_t NameBuffer[];
};

static_assert(sizeof(_MEMORY_SECTION_NAME<uint32_t>) == sizeof(_UNICODE_STRING<uint32_t>));
static_assert(sizeof(_MEMORY_SECTION_NAME<uint64_t>) == sizeof(_UNICODE_STRING<uint64_t>));

} /* namespace structs */

template <typename PtrType>
using MEMORY_SECTION_NAME_IMPL_BASE =
    MEMORY_INFORMATION_IMPL<MEMORY_SECTION_NAME, structs::_MEMORY_SECTION_NAME<PtrType>>;

template <typename PtrType>
class MEMORY_SECTION_NAME_IMPL final : public MEMORY_SECTION_NAME_IMPL_BASE<PtrType> {
  public:
    const std::string& SectionFileName() const override { return SectionFileName_->utf8(); }
    void SectionFileName(const std::string& value) override {
        SectionFileName_->set(value);
        this->data_->SectionFileName.Length = SectionFileName_->Length();
    }

    void write(std::ostream& os, const std::string& linePrefix = "") const override;
    Json::Value json() const override;

    MEMORY_SECTION_NAME_IMPL(const GuestVirtualAddress& gva, uint32_t buffer_size);

  private:
    std::optional<WStr> SectionFileName_;
};

} // namespace nt
} // namespace windows
} // namespace introvirt