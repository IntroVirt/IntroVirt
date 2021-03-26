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
#include <introvirt/windows/kernel/nt/syscall/types/key_information/KEY_BASIC_INFORMATION.hh>

namespace introvirt {
namespace windows {
namespace nt {

namespace structs {

struct _KEY_BASIC_INFORMATION {
    int64_t LastWriteTime;
    uint32_t TitleIndex;
    uint32_t NameLength;
    char16_t Name[];
};

static_assert(sizeof(_KEY_BASIC_INFORMATION) == 0x10);

} // namespace structs

class KEY_BASIC_INFORMATION_IMPL final : public KEY_BASIC_INFORMATION {
  public:
    WindowsTime LastWriteTime() const override {
        return WindowsTime::from_windows_time(ptr_->LastWriteTime);
    }
    void LastWriteTime(WindowsTime value) override { ptr_->LastWriteTime = value.windows_time(); }

    uint32_t TitleIndex() const override { return ptr_->TitleIndex; }
    void TitleIndex(uint32_t value) override { ptr_->TitleIndex = value; }

    const std::string& Name() const override { return Name_->utf8(); }
    void Name(const std::string& value) override {
        Name_->set(value);
        ptr_->NameLength = Name_->Length();
    }

    KEY_INFORMATION_CLASS KeyInformationClass() const override {
        return KEY_INFORMATION_CLASS::KeyBasicInformation;
    }

    guest_ptr<void> ptr() const override { return ptr_; }

    uint32_t buffer_size() const override { return buffer_size_; }

    void write(std::ostream& os, const std::string& linePrefix = "") const override;

    Json::Value json() const override;

    KEY_BASIC_INFORMATION_IMPL(const guest_ptr<void>& ptr, uint32_t buffer_size);

  private:
    const uint32_t buffer_size_;
    guest_ptr<structs::_KEY_BASIC_INFORMATION> ptr_;
    std::optional<WStr> Name_;
};

} // namespace nt
} // namespace windows
} // namespace introvirt