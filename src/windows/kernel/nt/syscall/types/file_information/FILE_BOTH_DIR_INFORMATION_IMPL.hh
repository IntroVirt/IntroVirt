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

#include "windows/kernel/nt/syscall/types/offset_iterable.hh"

#include <introvirt/core/memory/guest_ptr.hh>
#include <introvirt/windows/common/WStr.hh>
#include <introvirt/windows/kernel/nt/syscall/types/file_information/FILE_BOTH_DIR_INFORMATION.hh>

namespace introvirt {
namespace windows {
namespace nt {

namespace structs {

struct _FILE_BOTH_DIR_INFORMATION {
    uint32_t NextEntryOffset;
    uint32_t FileIndex;
    uint64_t CreationTime;
    uint64_t LastAccessTime;
    uint64_t LastWriteTime;
    uint64_t ChangeTime;
    uint64_t EndOfFile;
    uint64_t AllocationSize;
    uint32_t FileAttributes;
    uint32_t FileNameLength;
    uint32_t EaSize;
    uint8_t ShortNameLength;
    char16_t ShortName[12];
    char16_t FileName[];
};

} // namespace structs

class FILE_BOTH_DIR_INFORMATION_ENTRY_IMPL : public FILE_BOTH_DIR_INFORMATION_ENTRY {
  public:
    uint32_t NextEntryOffset() const override { return data_->NextEntryOffset; }
    void NextEntryOffset(uint32_t value) override { data_->NextEntryOffset = value; }

    const std::string& FileName() const override { return FileName_.utf8(); }
    void FileName(const std::string& FileName) override {
        FileName_.set(FileName);
        data_->FileNameLength = FileName_.Length();
    }

    const std::string ShortName() const override { return ShortName_.utf8(); }
    void ShortName(const std::string& ShortName) override {
        ShortName_.set(ShortName);
        data_->ShortNameLength = ShortName_.Length();
    }

    uint32_t FileIndex() const override { return data_->FileIndex; }
    void FileIndex(uint32_t FileIndex) override {}

    WindowsTime CreationTime() const override {
        return WindowsTime::from_windows_time(data_->CreationTime);
    }
    void CreationTime(WindowsTime CreationTime) override {
        data_->CreationTime = CreationTime.windows_time();
    }

    WindowsTime LastAccessTime() const override {
        return WindowsTime::from_windows_time(data_->LastAccessTime);
    }
    void LastAccessTime(WindowsTime LastAccessTime) override {
        data_->LastAccessTime = LastAccessTime.windows_time();
    }

    WindowsTime LastWriteTime() const override {
        return WindowsTime::from_windows_time(data_->LastWriteTime);
    }
    void LastWriteTime(WindowsTime LastWriteTime) override {
        data_->LastWriteTime = LastWriteTime.windows_time();
    }

    WindowsTime ChangeTime() const override {
        return WindowsTime::from_windows_time(data_->ChangeTime);
    }
    void ChangeTime(WindowsTime ChangeTime) override {
        data_->ChangeTime = ChangeTime.windows_time();
    }

    uint64_t EndOfFile() const override { return data_->EndOfFile; }
    void EndOfFile(uint64_t EndOfFile) override { data_->EndOfFile = EndOfFile; }

    uint64_t AllocationSize() const override { return data_->AllocationSize; }
    void AllocationSize(uint64_t AllocationSize) override {
        data_->AllocationSize = AllocationSize;
    }

    FILE_ATTRIBUTES FileAttributes() const override { return data_->FileAttributes; }
    void FileAttributes(FILE_ATTRIBUTES FileAttributes) override {
        data_->FileAttributes = FileAttributes;
    }

    uint32_t EaSize() const override { return data_->EaSize; }
    void EaSize(uint32_t EaSize) override { data_->EaSize = EaSize; }

    GuestVirtualAddress address() const override { return gva_; }
    uint32_t buffer_size() const override { return FileNameOffset + data_->FileNameLength; }

    FILE_BOTH_DIR_INFORMATION_ENTRY_IMPL(const GuestVirtualAddress& gva)
        : gva_(gva), data_(gva),
          ShortName_(gva_ + ShortNameOffset, data_->ShortNameLength, ShortNameMaxLen),
          FileName_(gva_ + FileNameOffset, data_->FileNameLength) {}

  private:
    static constexpr int ShortNameOffset = offsetof(structs::_FILE_BOTH_DIR_INFORMATION, ShortName);
    static constexpr int ShortNameMaxLen = sizeof(structs::_FILE_BOTH_DIR_INFORMATION::ShortName);
    static constexpr int FileNameOffset = offsetof(structs::_FILE_BOTH_DIR_INFORMATION, FileName);

    const GuestVirtualAddress gva_;
    guest_ptr<structs::_FILE_BOTH_DIR_INFORMATION> data_;
    WStr ShortName_;
    WStr FileName_;
};

class FILE_BOTH_DIR_INFORMATION_IMPL final
    : public offset_iterable<FILE_BOTH_DIR_INFORMATION_ENTRY, FILE_BOTH_DIR_INFORMATION> {
  public:
    FILE_INFORMATION_CLASS FileInformationClass() const override {
        return FILE_INFORMATION_CLASS::FileBothDirectoryInformation;
    }

    GuestVirtualAddress address() const override { return first_entry_; }

    uint32_t buffer_size() const override { return buffer_size_; }

    void write(std::ostream& os, const std::string& linePrefix = "") const override;

    Json::Value json() const override;

    FILE_BOTH_DIR_INFORMATION_IMPL(const GuestVirtualAddress& gva, uint32_t buffer_size);

  private:
};

} // namespace nt
} // namespace windows
} // namespace introvirt