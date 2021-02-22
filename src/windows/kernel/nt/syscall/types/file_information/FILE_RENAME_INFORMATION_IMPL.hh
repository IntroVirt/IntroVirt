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
#include <introvirt/windows/kernel/nt/syscall/types/file_information/FILE_RENAME_INFORMATION.hh>

namespace introvirt {
namespace windows {
namespace nt {

namespace structs {

template <typename PtrType>
struct _FILE_RENAME_INFORMATION {
    // TODO: There's also a Flags member for FileRenameInformationEx
    // The flag 0x1 corresponds to ReplaceIfExists, so it should be compatible
    PtrType ReplaceIfExists;
    PtrType RootDirectory;
    uint32_t FileNameLength;
    char16_t FileName[];
} __attribute__((packed));

static_assert(sizeof(_FILE_RENAME_INFORMATION<uint32_t>) == 0xC);
static_assert(sizeof(_FILE_RENAME_INFORMATION<uint64_t>) == 0x14);

} // namespace structs

template <typename PtrType>
class FILE_RENAME_INFORMATION_IMPL final : public FILE_RENAME_INFORMATION {
  public:
    bool ReplaceIfExists() const override { return data_->ReplaceIfExists; }
    uint64_t RootDirectory() const override { return data_->RootDirectory; }
    const std::string& FileName() const override { return FileName_->utf8(); }

    void ReplaceIfExists(bool value) override { data_->ReplaceIfExists = value; }
    void RootDirectory(uint64_t value) override { data_->RootDirectory = value; }
    void FileName(const std::string& value) override {
        FileName_->set(value);
        data_->FileNameLength = FileName_->Length();
    }

    FILE_INFORMATION_CLASS FileInformationClass() const override {
        return FILE_INFORMATION_CLASS::FileRenameInformation;
    }

    GuestVirtualAddress address() const override { return gva_; }

    uint32_t buffer_size() const override { return buffer_size_; }

    void write(std::ostream& os, const std::string& linePrefix = "") const override;

    Json::Value json() const override;

    FILE_RENAME_INFORMATION_IMPL(const GuestVirtualAddress& gva, uint32_t buffer_size);

  private:
    const GuestVirtualAddress gva_;
    const uint32_t buffer_size_;
    guest_ptr<structs::_FILE_RENAME_INFORMATION<PtrType>> data_;
    std::optional<WStr> FileName_;
};

} // namespace nt
} // namespace windows
} // namespace introvirt