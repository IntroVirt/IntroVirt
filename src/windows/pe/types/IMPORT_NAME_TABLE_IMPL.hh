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

#include "IMAGE_IMPORT_DESCRIPTOR_IMPL.hh"

#include <introvirt/windows/pe/types/IMAGE_OPTIONAL_HEADER.hh>
#include <introvirt/windows/pe/types/IMPORT_NAME_TABLE.hh>

#include <introvirt/core/domain/Vcpu.hh>
#include <introvirt/core/memory/guest_ptr.hh>

namespace introvirt {
namespace windows {
namespace pe {

template <typename PtrType>
class IMPORT_NAME_TABLE_IMPL final : public IMPORT_NAME_TABLE {
  public:
    const std::vector<std::unique_ptr<const IMAGE_IMPORT_DESCRIPTOR>>&
    ImportedModules() const override {
        return imports_;
    }

    IMPORT_NAME_TABLE_IMPL(const GuestVirtualAddress& image_base, GuestVirtualAddress pDescriptor,
                           uint32_t size) {

        const int count =
            (size / sizeof(structs::_IMAGE_IMPORT_DESCRIPTOR)) - 1; // last entry is full of 0s

        imports_.reserve(count);

        for (auto i = 0; i < count; ++i) {
            imports_.push_back(
                std::make_unique<IMAGE_IMPORT_DESCRIPTOR_IMPL<PtrType>>(image_base, pDescriptor));
            pDescriptor += sizeof(structs::_IMAGE_IMPORT_DESCRIPTOR);
        }
    }

  private:
    std::vector<std::unique_ptr<const IMAGE_IMPORT_DESCRIPTOR>> imports_;
};

} // namespace pe
} // namespace windows
} // namespace introvirt
