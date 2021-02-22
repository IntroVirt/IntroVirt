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

#include "FILE_INFORMATION.hh"

#include <introvirt/windows/kernel/nt/const/FILE_ATTRIBUTES.hh>
#include <introvirt/windows/kernel/nt/syscall/types/offset_iterator.hh>
#include <introvirt/windows/util/WindowsTime.hh>

#include <cstdint>
#include <string>

namespace introvirt {
namespace windows {
namespace nt {

class FILE_FULL_DIR_INFORMATION_ENTRY {
  public:
    virtual uint32_t NextEntryOffset() const = 0;
    virtual void NextEntryOffset(uint32_t value) = 0;

    virtual const std::string& FileName() const = 0;
    virtual void FileName(const std::string& FileName) = 0;

    virtual uint32_t FileIndex() const = 0;
    virtual void FileIndex(uint32_t FileIndex) = 0;

    virtual WindowsTime CreationTime() const = 0;
    virtual void CreationTime(WindowsTime CreationTime) = 0;

    virtual WindowsTime LastAccessTime() const = 0;
    virtual void LastAccessTime(WindowsTime LastAccessTime) = 0;

    virtual WindowsTime LastWriteTime() const = 0;
    virtual void LastWriteTime(WindowsTime LastWriteTime) = 0;

    virtual WindowsTime ChangeTime() const = 0;
    virtual void ChangeTime(WindowsTime ChangeTime) = 0;

    virtual uint64_t EndOfFile() const = 0;
    virtual void EndOfFile(uint64_t EndOfFile) = 0;

    virtual uint64_t AllocationSize() const = 0;
    virtual void AllocationSize(uint64_t AllocationSize) = 0;

    virtual FILE_ATTRIBUTES FileAttributes() const = 0;
    virtual void FileAttributes(FILE_ATTRIBUTES FileAttributes) = 0;

    virtual uint32_t EaSize() const = 0;
    virtual void EaSize(uint32_t EaSize) = 0;

    virtual GuestVirtualAddress address() const = 0;
    virtual uint32_t buffer_size() const = 0;

    // Assign this entry the value of another one
    virtual FILE_FULL_DIR_INFORMATION_ENTRY& operator=(const FILE_FULL_DIR_INFORMATION_ENTRY&) = 0;

    static std::shared_ptr<FILE_FULL_DIR_INFORMATION_ENTRY>
    make_shared(const GuestVirtualAddress& gva);

    virtual ~FILE_FULL_DIR_INFORMATION_ENTRY() = default;
};

class FILE_FULL_DIR_INFORMATION : public FILE_INFORMATION {
  public:
    using iterator = offset_iterator<FILE_FULL_DIR_INFORMATION_ENTRY, false>;
    using const_iterator = offset_iterator<FILE_FULL_DIR_INFORMATION_ENTRY, true>;

    virtual iterator begin() = 0;
    virtual iterator end() = 0;
    virtual iterator erase(const const_iterator& position) = 0;

    virtual const_iterator begin() const = 0;
    virtual const_iterator end() const = 0;
};

} /* namespace nt */
} /* namespace windows */
} /* namespace introvirt */