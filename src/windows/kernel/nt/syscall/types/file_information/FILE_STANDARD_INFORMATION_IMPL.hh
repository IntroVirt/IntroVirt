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
#include <introvirt/windows/kernel/nt/syscall/types/file_information/FILE_STANDARD_INFORMATION.hh>

namespace introvirt {
namespace windows {
namespace nt {

namespace structs {

// TODO: Do we need to align this properly for 32-bit ?
struct _FILE_STANDARD_INFORMATION {
    uint64_t AllocationSize; // offset   0x0 size   0x8
    uint64_t EndOfFile;      // offset   0x8 size   0x8
    uint32_t NumberOfLinks;  // offset  0x10 size   0x4
    uint8_t DeletePending;   // offset  0x14 size   0x1
    uint8_t Directory;       // offset  0x15 size   0x1
};

} // namespace structs

class FILE_STANDARD_INFORMATION_IMPL final : public FILE_STANDARD_INFORMATION {
  public:
    uint64_t AllocationSize() const override { return data_->AllocationSize; }
    uint64_t EndOfFile() const override { return data_->EndOfFile; }
    uint32_t NumberOfLinks() const override { return data_->NumberOfLinks; }
    bool DeletePending() const override { return data_->DeletePending; }
    bool Directory() const override { return data_->Directory; }

    void AllocationSize(uint64_t value) override { data_->AllocationSize = value; }
    void EndOfFile(uint64_t value) override { data_->EndOfFile = value; }
    void NumberOfLinks(uint32_t value) override { data_->NumberOfLinks = value; }
    void DeletePending(bool value) override { data_->DeletePending = value; }
    void Directory(bool value) override { data_->Directory = value; }

    FILE_INFORMATION_CLASS FileInformationClass() const override {
        return FILE_INFORMATION_CLASS::FileStandardInformation;
    }

    GuestVirtualAddress address() const override { return gva_; }

    uint32_t buffer_size() const override { return buffer_size_; }

    void write(std::ostream& os, const std::string& linePrefix = "") const override;

    Json::Value json() const override;

    FILE_STANDARD_INFORMATION_IMPL(const GuestVirtualAddress& gva, uint32_t buffer_size);

  private:
    const GuestVirtualAddress gva_;
    const uint32_t buffer_size_;
    guest_ptr<structs::_FILE_STANDARD_INFORMATION> data_;
};

} // namespace nt
} // namespace windows
} // namespace introvirt