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

#include "PROCESS_INFORMATION_IMPL.hh"

#include <introvirt/windows/common/WStr.hh>
#include <introvirt/windows/kernel/nt/syscall/types/process_information/PROCESS_WINDOW_INFORMATION.hh>

#include <cmath>
#include <optional>

namespace introvirt {
namespace windows {
namespace nt {

namespace structs {

struct __attribute__((packed)) _PROCESS_WINDOW_INFORMATION {
    uint32_t WindowFlags;
    uint16_t WindowTitleLength;
    char16_t WindowTitle[];
};

static_assert(sizeof(_PROCESS_WINDOW_INFORMATION) == 0x6);
static_assert(offsetof(_PROCESS_WINDOW_INFORMATION, WindowTitle) == 0x6);

} // namespace structs

using PROCESS_WINDOW_INFORMATION_IMPL_BASE =
    PROCESS_INFORMATION_IMPL<PROCESS_WINDOW_INFORMATION, structs::_PROCESS_WINDOW_INFORMATION>;

class PROCESS_WINDOW_INFORMATION_IMPL final : public PROCESS_WINDOW_INFORMATION_IMPL_BASE {
  public:
    uint32_t WindowFlags() const override { return this->data_->WindowFlags; }
    void WindowFlags(uint32_t WindowFlags) override { this->data_->WindowFlags = WindowFlags; }

    const std::string& WindowTitle() const override { return WindowTitle_->utf8(); }
    void WindowTitle(const std::string& value) override {
        WindowTitle_->set(value);
        this->data_->WindowTitleLength = WindowTitle_->Length();
    }

    void write(std::ostream& os, const std::string& linePrefix = "") const override;
    Json::Value json() const override;

    PROCESS_WINDOW_INFORMATION_IMPL(const GuestVirtualAddress& gva, uint32_t buffer_size)
        : PROCESS_WINDOW_INFORMATION_IMPL_BASE(PROCESS_INFORMATION_CLASS::ProcessWindowInformation,
                                               gva, buffer_size) {

        const uint16_t WindowsTitleMaxLength =
            buffer_size_ - offsetof(structs::_PROCESS_WINDOW_INFORMATION, WindowTitle);

        const uint16_t WindowTitleLength =
            std::min(WindowsTitleMaxLength, this->data_->WindowTitleLength);

        WindowTitle_.emplace(this->gva_ +
                                 offsetof(structs::_PROCESS_WINDOW_INFORMATION, WindowTitle),
                             WindowTitleLength, WindowsTitleMaxLength);
    }

  private:
    std::optional<WStr> WindowTitle_;
};

} // namespace nt
} // namespace windows
} // namespace introvirt