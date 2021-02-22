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
#include <introvirt/windows/pe/types/IMAGE_OPTIONAL_HEADER.hh>
#include <introvirt/windows/pe/types/IMAGE_RESOURCE_DIRECTORY.hh>
#include <introvirt/windows/pe/types/IMAGE_RESOURCE_DIRECTORY_ENTRY.hh>

#include <map>

using namespace std;

namespace introvirt {
namespace windows {
namespace pe {

namespace structs {

struct _IMAGE_RESOURCE_DIRECTORY {
    uint32_t Characteristics;
    uint32_t TimeDateStamp;
    uint16_t MajorVersion;
    uint16_t MinorVersion;
    uint16_t NumberOfNamedEntries;
    uint16_t NumberOfIdEntries;
};

} // namespace structs

class IMAGE_RESOURCE_DIRECTORY_IMPL final : public IMAGE_RESOURCE_DIRECTORY {
  public:
    uint32_t Characteristics() const override { return data_->Characteristics; }
    uint32_t TimeDateStamp() const override { return data_->TimeDateStamp; }
    uint16_t MajorVersion() const override { return data_->MajorVersion; }
    uint16_t MinorVersion() const override { return data_->MinorVersion; }
    uint16_t NumberOfNamedEntries() const override { return data_->NumberOfNamedEntries; }
    uint16_t NumberOfIdEntries() const override { return data_->NumberOfIdEntries; }

    const std::vector<std::unique_ptr<const IMAGE_RESOURCE_DIRECTORY_ENTRY>>&
    entries() const override {
        return entries_;
    }

    const IMAGE_RESOURCE_DIRECTORY_ENTRY* entry(uint16_t Id) const override {
        auto iter = id_to_entry_.find(Id);
        if (iter != id_to_entry_.end()) {
            return iter->second;
        }
        return nullptr;
    }

    IMAGE_RESOURCE_DIRECTORY_IMPL(const GuestVirtualAddress& pImageBase,
                                  const GuestVirtualAddress& pResourceBase,
                                  const GuestVirtualAddress& pResourceDirectory);

  private:
    guest_ptr<structs::_IMAGE_RESOURCE_DIRECTORY> data_;
    std::vector<std::unique_ptr<const IMAGE_RESOURCE_DIRECTORY_ENTRY>> entries_;
    std::map<uint16_t, const IMAGE_RESOURCE_DIRECTORY_ENTRY*> id_to_entry_;
};

} // namespace pe
} // namespace windows
} // namespace introvirt
