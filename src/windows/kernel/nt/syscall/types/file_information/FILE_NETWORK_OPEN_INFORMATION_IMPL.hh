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
#include <introvirt/windows/kernel/nt/syscall/types/file_information/FILE_NETWORK_OPEN_INFORMATION.hh>

namespace introvirt {
namespace windows {
namespace nt {

namespace structs {

struct _FILE_NETWORK_OPEN_INFORMATION {
    uint64_t CreationTime;   // offset   0x0 size   0x8
    uint64_t LastAccessTime; // offset   0x8 size   0x8
    uint64_t LastWriteTime;  // offset  0x10 size   0x8
    uint64_t ChangeTime;     // offset  0x18 size   0x8
    uint64_t AllocationSize;
    uint64_t EndOfFile;
    uint32_t FileAttributes; // offset  0x20 size   0x4
    uint32_t reserved;
};

} // namespace structs

class FILE_NETWORK_OPEN_INFORMATION_IMPL final : public FILE_NETWORK_OPEN_INFORMATION {
  public:
    WindowsTime CreationTime() const override {
        return WindowsTime::from_windows_time(ptr_->CreationTime);
    }
    WindowsTime LastAccessTime() const override {
        return WindowsTime::from_windows_time(ptr_->LastAccessTime);
    }
    WindowsTime LastWriteTime() const override {
        return WindowsTime::from_windows_time(ptr_->LastWriteTime);
    }
    WindowsTime ChangeTime() const override {
        return WindowsTime::from_windows_time(ptr_->ChangeTime);
    }
    uint64_t EndOfFile() const override { return ptr_->EndOfFile; }

    FILE_ATTRIBUTES FileAttributes() const override {
        return FILE_ATTRIBUTES(ptr_->FileAttributes);
    }

    void CreationTime(WindowsTime time) override { ptr_->CreationTime = time.windows_time(); }
    void LastAccessTime(WindowsTime time) override { ptr_->LastAccessTime = time.windows_time(); }
    void LastWriteTime(WindowsTime time) override { ptr_->LastWriteTime = time.windows_time(); }
    void ChangeTime(WindowsTime time) override { ptr_->ChangeTime = time.windows_time(); }
    void EndOfFile(uint64_t eof) override { ptr_->EndOfFile = eof; }
    void FileAttributes(FILE_ATTRIBUTES atts) override { ptr_->FileAttributes = atts.get(); }

    FILE_INFORMATION_CLASS FileInformationClass() const override {
        return FILE_INFORMATION_CLASS::FileNetworkOpenInformation;
    }

    guest_ptr<void> ptr() const override { return ptr_; }

    uint32_t buffer_size() const override { return buffer_size_; }

    void write(std::ostream& os, const std::string& linePrefix = "") const override;

    Json::Value json() const override;

    FILE_NETWORK_OPEN_INFORMATION_IMPL(const guest_ptr<void>& ptr);
    FILE_NETWORK_OPEN_INFORMATION_IMPL(const guest_ptr<void>& ptr, uint32_t buffer_size);

  private:
    const uint32_t buffer_size_;
    guest_ptr<structs::_FILE_NETWORK_OPEN_INFORMATION> ptr_;
};

} // namespace nt
} // namespace windows
} // namespace introvirt