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
#include <introvirt/windows/kernel/nt/syscall/types/file_information/FILE_BASIC_INFORMATION.hh>

namespace introvirt {
namespace windows {
namespace nt {

namespace structs {

struct _FILE_BASIC_INFORMATION { // 0x24 bytes
    uint64_t CreationTime;       // offset   0x0 size   0x8
    uint64_t LastAccessTime;     // offset   0x8 size   0x8
    uint64_t LastWriteTime;      // offset  0x10 size   0x8
    uint64_t ChangeTime;         // offset  0x18 size   0x8
    uint32_t FileAttributes;     // offset  0x20 size   0x4
} __attribute__((packed));

} // namespace structs

class FILE_BASIC_INFORMATION_IMPL final : public FILE_BASIC_INFORMATION {
  public:
    /* Getters */
    WindowsTime CreationTime() const override {
        return WindowsTime::from_windows_time(data_->CreationTime);
    }
    WindowsTime LastAccessTime() const override {
        return WindowsTime::from_windows_time(data_->LastAccessTime);
    }
    WindowsTime LastWriteTime() const override {
        return WindowsTime::from_windows_time(data_->LastWriteTime);
    }
    WindowsTime ChangeTime() const override {
        return WindowsTime::from_windows_time(data_->ChangeTime);
    }
    FILE_ATTRIBUTES FileAttributes() const override { return data_->FileAttributes; }

    /* Setters - These change the values in the guest! */
    void CreationTime(WindowsTime time) override { data_->ChangeTime = time.windows_time(); }
    void LastAccessTime(WindowsTime time) override { data_->LastAccessTime = time.windows_time(); }
    void LastWriteTime(WindowsTime time) override { data_->LastWriteTime = time.windows_time(); }
    void ChangeTime(WindowsTime time) override { data_->ChangeTime = time.windows_time(); }
    void FileAttributes(FILE_ATTRIBUTES atts) override { data_->FileAttributes = atts; }

    FILE_INFORMATION_CLASS FileInformationClass() const override {
        return FILE_INFORMATION_CLASS::FileBasicInformation;
    }

    GuestVirtualAddress address() const override { return gva_; }

    uint32_t buffer_size() const override { return buffer_size_; }

    void write(std::ostream& os, const std::string& linePrefix = "") const override;

    Json::Value json() const override;

    FILE_BASIC_INFORMATION_IMPL(const GuestVirtualAddress& gva);
    FILE_BASIC_INFORMATION_IMPL(const GuestVirtualAddress& gva, uint32_t buffer_size);

  private:
    const GuestVirtualAddress gva_;
    const uint32_t buffer_size_;
    guest_ptr<structs::_FILE_BASIC_INFORMATION> data_;
};

} // namespace nt
} // namespace windows
} // namespace introvirt