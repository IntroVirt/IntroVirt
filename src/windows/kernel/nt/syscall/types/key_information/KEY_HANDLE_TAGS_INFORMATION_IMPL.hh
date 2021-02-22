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
#include <introvirt/windows/kernel/nt/syscall/types/key_information/KEY_HANDLE_TAGS_INFORMATION.hh>

namespace introvirt {
namespace windows {
namespace nt {

namespace structs {

struct _KEY_HANDLE_TAGS_INFORMATION {
    uint32_t HandleTags;
} __attribute__((packed));

static_assert(sizeof(_KEY_HANDLE_TAGS_INFORMATION) == 0x4);

} // namespace structs

class KEY_HANDLE_TAGS_INFORMATION_IMPL final : public KEY_HANDLE_TAGS_INFORMATION {
  public:
    uint32_t HandleTags() const override { return data_->HandleTags; }
    void HandleTags(uint32_t value) override { data_->HandleTags = value; }

    KEY_INFORMATION_CLASS KeyInformationClass() const override {
        return KEY_INFORMATION_CLASS::KeyHandleTagsInformation;
    }

    GuestVirtualAddress address() const override { return gva_; }

    uint32_t buffer_size() const override { return buffer_size_; }

    void write(std::ostream& os, const std::string& linePrefix = "") const override;

    Json::Value json() const override;

    KEY_HANDLE_TAGS_INFORMATION_IMPL(const GuestVirtualAddress& gva, uint32_t buffer_size);

  private:
    const GuestVirtualAddress gva_;
    const uint32_t buffer_size_;
    guest_ptr<structs::_KEY_HANDLE_TAGS_INFORMATION> data_;
};

} // namespace nt
} // namespace windows
} // namespace introvirt