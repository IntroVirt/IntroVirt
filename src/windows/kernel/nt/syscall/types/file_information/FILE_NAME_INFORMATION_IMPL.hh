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
#include <introvirt/windows/kernel/nt/syscall/types/file_information/FILE_NAME_INFORMATION.hh>

namespace introvirt {
namespace windows {
namespace nt {

namespace structs {

struct _FILE_NAME_INFORMATION {
    uint32_t FileNameLength;
    char16_t FileName[];
};

static_assert(sizeof(_FILE_NAME_INFORMATION) == 0x4);

} // namespace structs

class FILE_NAME_INFORMATION_IMPL final : public FILE_NAME_INFORMATION {
  public:
    const std::string& FileName() const override { return FileName_->utf8(); }
    void FileName(const std::string& value) override {
        FileName_->set(value);
        data_->FileNameLength = FileName_->Length();
    }

    FILE_INFORMATION_CLASS FileInformationClass() const override {
        return FILE_INFORMATION_CLASS::FileNameInformation;
    }

    GuestVirtualAddress address() const override { return gva_; }

    uint32_t buffer_size() const override { return buffer_size_; }

    void write(std::ostream& os, const std::string& linePrefix = "") const override;

    Json::Value json() const override;

    FILE_NAME_INFORMATION_IMPL(const GuestVirtualAddress& gva, uint32_t buffer_size);

  private:
    const GuestVirtualAddress gva_;
    const uint32_t buffer_size_;
    guest_ptr<structs::_FILE_NAME_INFORMATION> data_;
    std::optional<WStr> FileName_;
};

} // namespace nt
} // namespace windows
} // namespace introvirt