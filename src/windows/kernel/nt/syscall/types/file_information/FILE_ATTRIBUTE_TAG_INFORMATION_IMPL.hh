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
#include <introvirt/windows/kernel/nt/syscall/types/file_information/FILE_ATTRIBUTE_TAG_INFORMATION.hh>

namespace introvirt {
namespace windows {
namespace nt {

namespace structs {

struct _FILE_ATTRIBUTE_TAG_INFORMATION {
    uint32_t FileAttributes;
    uint32_t ReparseTag;
};

} // namespace structs

class FILE_ATTRIBUTE_TAG_INFORMATION_IMPL final : public FILE_ATTRIBUTE_TAG_INFORMATION {
  public:
    FILE_ATTRIBUTES FileAttributes() const override { return ptr_->FileAttributes; }
    void FileAttributes(FILE_ATTRIBUTES attributes) override { ptr_->FileAttributes = attributes; }

    uint32_t ReparseTag() const override { return ptr_->ReparseTag; }
    void ReparseTag(uint32_t value) override { ptr_->ReparseTag = value; }

    FILE_INFORMATION_CLASS FileInformationClass() const override {
        return FILE_INFORMATION_CLASS::FileAttributeTagInformation;
    }

    guest_ptr<void> ptr() const override { return ptr_; }

    uint32_t buffer_size() const override { return buffer_size_; }

    void write(std::ostream& os, const std::string& linePrefix = "") const override;

    Json::Value json() const override;

    FILE_ATTRIBUTE_TAG_INFORMATION_IMPL(const guest_ptr<void>& ptr, uint32_t buffer_size);

  private:
    guest_ptr<structs::_FILE_ATTRIBUTE_TAG_INFORMATION> ptr_;
    const uint32_t buffer_size_;
};

} // namespace nt
} // namespace windows
} // namespace introvirt