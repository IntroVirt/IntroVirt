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

#include "IMAGE_RESOURCE_DATA_ENTRY_IMPL.hh"
#include "IMAGE_RESOURCE_DIRECTORY_IMPL.hh"

#include <introvirt/core/exception/InvalidMethodException.hh>
#include <introvirt/core/memory/guest_ptr.hh>
#include <introvirt/util/compiler.hh>
#include <introvirt/windows/common/WStr.hh>
#include <introvirt/windows/pe/exception/PeException.hh>
#include <introvirt/windows/pe/types/IMAGE_RESOURCE_DIRECTORY.hh>
#include <introvirt/windows/pe/types/IMAGE_RESOURCE_DIRECTORY_ENTRY.hh>

namespace introvirt {
namespace windows {
namespace pe {

class IMAGE_RESOURCE_DIRECTORY_IMPL;

namespace structs {

struct _IMAGE_RESOURCE_DIRECTORY_ENTRY {
    union {
        struct {
            uint32_t NameOffset : 31;
            uint32_t NameIsString : 1;
        } __attribute__((ms_struct));
        uint32_t Name;
        uint16_t Id;
    };
    union {
        uint32_t OffsetToData;
        struct {
            uint32_t OffsetToDirectory : 31;
            uint32_t DataIsDirectory : 1;
        } __attribute__((ms_struct));
    };
};

} // namespace structs

class IMAGE_RESOURCE_DIRECTORY_ENTRY_IMPL final : public IMAGE_RESOURCE_DIRECTORY_ENTRY {
  public:
    bool NameIsString() const override { return data_->NameIsString; }

    const std::string& Name() const override {
        if (unlikely(!NameIsString()))
            throw InvalidMethodException();
        return Name_;
    }

    uint16_t Id() const override {
        if (unlikely(NameIsString()))
            throw InvalidMethodException();
        return data_->Id;
    }

    bool DataIsDirectory() const override { return data_->DataIsDirectory; }

    const IMAGE_RESOURCE_DIRECTORY* Directory() const override {
        if (directory_)
            return &*(directory_);
        return nullptr;
    }
    const IMAGE_RESOURCE_DATA_ENTRY* Data() const override {
        if (data_entry_)
            return &*(data_entry_);
        return nullptr;
    }

    IMAGE_RESOURCE_DIRECTORY_ENTRY_IMPL(const GuestVirtualAddress& pImageBase,
                                        const GuestVirtualAddress& pResourceSection,
                                        const GuestVirtualAddress& pResourceEntry);

  private:
    guest_ptr<structs::_IMAGE_RESOURCE_DIRECTORY_ENTRY> data_;

    std::string Name_;
    std::optional<IMAGE_RESOURCE_DIRECTORY_IMPL> directory_;
    std::optional<IMAGE_RESOURCE_DATA_ENTRY_IMPL> data_entry_;
};

} // namespace pe
} // namespace windows
} // namespace introvirt
