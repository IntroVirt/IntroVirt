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

#include <introvirt/core/memory/guest_ptr.hh>
#include <introvirt/windows/common/WStr.hh>
#include <introvirt/windows/exception/StringConversionException.hh>
#include <introvirt/windows/kernel/nt/syscall/types/key_information/KEY_NODE_INFORMATION.hh>

#include <optional>

namespace introvirt {
namespace windows {
namespace nt {

namespace structs {

struct _KEY_NODE_INFORMATION {
    int64_t LastWriteTime;
    uint32_t TitleIndex;
    uint32_t ClassOffset;
    uint32_t ClassLength;
    uint32_t NameLength;
    char16_t Name[];
};
static_assert(sizeof(_KEY_NODE_INFORMATION) == 0x18);

} // namespace structs

class KEY_NODE_INFORMATION_IMPL final : public KEY_NODE_INFORMATION {
  public:
    WindowsTime LastWriteTime() const override {
        return WindowsTime::from_windows_time(data_->LastWriteTime);
    }
    void LastWriteTime(WindowsTime value) override { data_->LastWriteTime = value.windows_time(); }

    uint32_t TitleIndex() const override { return data_->TitleIndex; }
    void TitleIndex(uint32_t value) override { data_->TitleIndex = value; }

    const std::string& Class() const override { return ClassName_->utf8(); }
    void Class(const std::string& value) override { ClassName_->set(value); }

    const std::string& Name() const override { return Name_->utf8(); }
    void Name(const std::string& value) override { Name_->set(value); }

    KEY_INFORMATION_CLASS KeyInformationClass() const override {
        return KEY_INFORMATION_CLASS::KeyNodeInformation;
    }

    GuestVirtualAddress address() const override { return gva_; }

    uint32_t buffer_size() const override { return buffer_size_; }

    void write(std::ostream& os, const std::string& linePrefix = "") const override;

    Json::Value json() const override;

    KEY_NODE_INFORMATION_IMPL(const GuestVirtualAddress& gva, uint32_t buffer_size);

  private:
    const GuestVirtualAddress gva_;
    const uint32_t buffer_size_;
    guest_ptr<structs::_KEY_NODE_INFORMATION> data_;
    std::optional<WStr> ClassName_;
    std::optional<WStr> Name_;
};

} // namespace nt
} // namespace windows
} // namespace introvirt