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
#include <introvirt/windows/kernel/nt/syscall/types/file_information/FILE_ID_BOTH_DIR_INFORMATION.hh>

namespace introvirt {
namespace windows {
namespace nt {

namespace structs {

struct _FILE_ID_BOTH_DIR_INFORMATION {
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
    uint64_t FileId;
    char16_t FileName[];
};

} // namespace structs

class FILE_ID_BOTH_DIR_INFORMATION_ENTRY_IMPL : public FILE_ID_BOTH_DIR_INFORMATION_ENTRY {
  public:
    uint32_t NextEntryOffset() const override { return ptr_->NextEntryOffset; }
    void NextEntryOffset(uint32_t value) override { ptr_->NextEntryOffset = value; }

    const std::string& FileName() const override { return FileName_.utf8(); }
    void FileName(const std::string& FileName) override {
        FileName_.set(FileName);
        ptr_->FileNameLength = FileName_.Length();
    }

    const std::string ShortName() const override { return ShortName_.utf8(); }
    void ShortName(const std::string& ShortName) override {
        ShortName_.set(ShortName);
        ptr_->ShortNameLength = ShortName_.Length();
    }

    uint32_t FileIndex() const override { return ptr_->FileIndex; }
    void FileIndex(uint32_t FileIndex) override {}

    WindowsTime CreationTime() const override {
        return WindowsTime::from_windows_time(ptr_->CreationTime);
    }
    void CreationTime(WindowsTime CreationTime) override {
        ptr_->CreationTime = CreationTime.windows_time();
    }

    WindowsTime LastAccessTime() const override {
        return WindowsTime::from_windows_time(ptr_->LastAccessTime);
    }
    void LastAccessTime(WindowsTime LastAccessTime) override {
        ptr_->LastAccessTime = LastAccessTime.windows_time();
    }

    WindowsTime LastWriteTime() const override {
        return WindowsTime::from_windows_time(ptr_->LastWriteTime);
    }
    void LastWriteTime(WindowsTime LastWriteTime) override {
        ptr_->LastWriteTime = LastWriteTime.windows_time();
    }

    WindowsTime ChangeTime() const override {
        return WindowsTime::from_windows_time(ptr_->ChangeTime);
    }
    void ChangeTime(WindowsTime ChangeTime) override {
        ptr_->ChangeTime = ChangeTime.windows_time();
    }

    uint64_t EndOfFile() const override { return ptr_->EndOfFile; }
    void EndOfFile(uint64_t EndOfFile) override { ptr_->EndOfFile = EndOfFile; }

    uint64_t AllocationSize() const override { return ptr_->AllocationSize; }
    void AllocationSize(uint64_t AllocationSize) override { ptr_->AllocationSize = AllocationSize; }

    FILE_ATTRIBUTES FileAttributes() const override { return ptr_->FileAttributes; }
    void FileAttributes(FILE_ATTRIBUTES FileAttributes) override {
        ptr_->FileAttributes = FileAttributes;
    }

    uint32_t EaSize() const override { return ptr_->EaSize; }
    void EaSize(uint32_t EaSize) override { ptr_->EaSize = EaSize; }

    uint64_t FileId() const override { return ptr_->FileId; }
    void FileId(uint64_t FileId) override { ptr_->FileId = FileId; }

    guest_ptr<void> ptr() const override { return ptr_; }
    uint32_t buffer_size() const override { return FileNameOffset + ptr_->FileNameLength; }

    FILE_ID_BOTH_DIR_INFORMATION_ENTRY_IMPL(const guest_ptr<void>& ptr)
        : ptr_(ptr), ShortName_(ptr_ + ShortNameOffset, ShortNameMaxLen, ptr_->ShortNameLength),
          FileName_(ptr_ + FileNameOffset, ptr_->FileNameLength) {}

  private:
    static constexpr int ShortNameOffset =
        offsetof(structs::_FILE_ID_BOTH_DIR_INFORMATION, ShortName);
    static constexpr int ShortNameMaxLen =
        sizeof(structs::_FILE_ID_BOTH_DIR_INFORMATION::ShortName);
    static constexpr int FileNameOffset =
        offsetof(structs::_FILE_ID_BOTH_DIR_INFORMATION, FileName);

    guest_ptr<structs::_FILE_ID_BOTH_DIR_INFORMATION> ptr_;
    WStr ShortName_;
    WStr FileName_;
};

class FILE_ID_BOTH_DIR_INFORMATION_IMPL final
    : public offset_iterable<FILE_ID_BOTH_DIR_INFORMATION_ENTRY, FILE_ID_BOTH_DIR_INFORMATION> {
  public:
    FILE_INFORMATION_CLASS FileInformationClass() const override {
        return FILE_INFORMATION_CLASS::FileIdBothDirectoryInformation;
    }

    guest_ptr<void> ptr() const override { return first_entry_; }

    uint32_t buffer_size() const override { return buffer_size_; }

    void write(std::ostream& os, const std::string& linePrefix = "") const override;

    Json::Value json() const override;

    FILE_ID_BOTH_DIR_INFORMATION_IMPL(const guest_ptr<void>& ptr, uint32_t buffer_size);

  private:
};

} // namespace nt
} // namespace windows
} // namespace introvirt