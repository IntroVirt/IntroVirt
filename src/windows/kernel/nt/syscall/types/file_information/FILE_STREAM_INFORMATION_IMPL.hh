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
#include <introvirt/windows/kernel/nt/syscall/types/file_information/FILE_STREAM_INFORMATION.hh>

namespace introvirt {
namespace windows {
namespace nt {

namespace structs {

struct _FILE_STREAM_INFORMATION {
    uint32_t NextEntryOffset;
    uint32_t StreamNameLength;
    int64_t StreamSize;
    int64_t StreamAllocationSize;
    char16_t StreamName[];
};

static_assert(sizeof(_FILE_STREAM_INFORMATION) == 0x18);

} // namespace structs

class FILE_STREAM_INFORMATION_ENTRY_IMPL final : public FILE_STREAM_INFORMATION_ENTRY {
  public:
    uint32_t NextEntryOffset() const override { return data_->NextEntryOffset; }
    void NextEntryOffset(uint32_t value) override { data_->NextEntryOffset = value; }

    const std::string& StreamName() const override { return StreamName_.utf8(); }
    void StreamName(const std::string& StreamName) override {
        StreamName_.set(StreamName);
        data_->StreamNameLength = StreamName_.Length();
    }

    int64_t StreamSize() const override { return data_->StreamSize; }
    void StreamSize(int64_t StreamSize) override { data_->StreamSize = StreamSize; }

    int64_t StreamAllocationSize() const override { return data_->StreamAllocationSize; };
    void StreamAllocationSize(int64_t StreamAllocationSize) override {
        data_->StreamAllocationSize = StreamAllocationSize;
    };

    GuestVirtualAddress address() const override { return gva_; }
    uint32_t buffer_size() const override {
        return offsetof(structs::_FILE_STREAM_INFORMATION, StreamName) + data_->StreamSize;
    }

    FILE_STREAM_INFORMATION_ENTRY_IMPL&
    operator=(const FILE_STREAM_INFORMATION_ENTRY& src) override;

    FILE_STREAM_INFORMATION_ENTRY_IMPL(const GuestVirtualAddress& gva)
        : gva_(gva), data_(gva_),
          StreamName_(gva_ + offsetof(structs::_FILE_STREAM_INFORMATION, StreamName),
                      data_->StreamNameLength) {}

  private:
    GuestVirtualAddress gva_;
    guest_ptr<structs::_FILE_STREAM_INFORMATION> data_;
    WStr StreamName_;
};

class FILE_STREAM_INFORMATION_IMPL final
    : public offset_iterable<FILE_STREAM_INFORMATION_ENTRY, FILE_STREAM_INFORMATION> {
  public:
    FILE_INFORMATION_CLASS FileInformationClass() const override {
        return FILE_INFORMATION_CLASS::FileStreamInformation;
    }

    GuestVirtualAddress address() const override { return first_entry_; }

    uint32_t buffer_size() const override { return buffer_size_; }

    void write(std::ostream& os, const std::string& linePrefix = "") const override;

    Json::Value json() const override;

    FILE_STREAM_INFORMATION_IMPL(const GuestVirtualAddress& gva, uint32_t buffer_size);

  private:
};

} // namespace nt
} // namespace windows
} // namespace introvirt