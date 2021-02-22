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

#include "UnwindInfoImpl.hh"

#include <introvirt/core/exception/InvalidMethodException.hh>
#include <introvirt/core/memory/guest_ptr.hh>
#include <introvirt/windows/pe/types/RUNTIME_FUNCTION.hh>

#include <memory>

namespace introvirt {
namespace windows {
namespace pe {

class IMAGE_EXCEPTION_SECTION_IMPL;

namespace structs {

struct _RUNTIME_FUNCTION {
    uint32_t BeginAddress;
    uint32_t EndAddress;
    uint32_t UnwindData;
};

} // namespace structs

class RUNTIME_FUNCTION_IMPL : public RUNTIME_FUNCTION {
  public:
    uint32_t BeginAddress() const override { return data_->BeginAddress; }
    uint32_t EndAddress() const override { return data_->EndAddress; }

    const UnwindInfo* UnwindData() const override;
    bool is_chained() const override { return (data_->UnwindData & 0x01) == 0x01; }

    const RUNTIME_FUNCTION* chained_function() const override;

    RUNTIME_FUNCTION_IMPL(const IMAGE_EXCEPTION_SECTION_IMPL* section,
                          const GuestVirtualAddress& gva)
        : section_(section), data_(gva), Chained_(nullptr) {}

  private:
    const IMAGE_EXCEPTION_SECTION_IMPL* section_; // TODO: Can this be a reference?
    guest_ptr<structs::_RUNTIME_FUNCTION> data_;
    mutable std::unique_ptr<UnwindInfo> UnwindData_;
    mutable const RUNTIME_FUNCTION* Chained_;
};

} // namespace pe
} // namespace windows
} // namespace introvirt
