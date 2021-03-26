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
#include <introvirt/windows/pe/types/IMAGE_SECTION_HEADER.hh>

#include <cstring>
#include <vector>

using namespace std;

namespace introvirt {
namespace windows {
namespace pe {

namespace structs {

struct _IMAGE_SECTION_HEADER {
    char Name[0x8]; // offset   0x0 size   0x8
    union {
        uint32_t PhysicalAddress;  // offset   0x0 size   0x4
        uint32_t VirtualSize;      // offset   0x0 size   0x4
    } Misc;                        // offset   0x8 size   0x4
    uint32_t VirtualAddress;       // offset   0xc size   0x4
    uint32_t SizeOfRawData;        // offset  0x10 size   0x4
    uint32_t PointerToRawData;     // offset  0x14 size   0x4
    uint32_t PointerToRelocations; // offset  0x18 size   0x4
    uint32_t PointerToLinenumbers; // offset  0x1c size   0x4
    uint16_t NumberOfRelocations;  // offset  0x20 size   0x2
    uint16_t NumberOfLinenumbers;  // offset  0x22 size   0x2
    uint32_t Characteristics;      // offset  0x24 size   0x4
};

} // namespace structs

class IMAGE_SECTION_HEADER_IMPL final : public IMAGE_SECTION_HEADER {
  public:
    const std::string& Name() const override { return Name_; }

    virtual uint32_t VirtualSize() const override { return ptr_->Misc.VirtualSize; }

    virtual guest_ptr<void> VirtualAddress() const override {
        return image_base_ + ptr_->VirtualAddress;
    }

    virtual uint32_t SizeOfRawData() const override { return ptr_->SizeOfRawData; }

    guest_ptr<void> ptr() const { return ptr_; }

    IMAGE_SECTION_HEADER_IMPL(const guest_ptr<void>& image_base, const guest_ptr<void>& ptr)
        : image_base_(image_base), ptr_(ptr) {
        Name_ = std::string(ptr_->Name, strnlen(ptr_->Name, sizeof(ptr_->Name)));
    }

  private:
    const guest_ptr<void> image_base_;
    guest_ptr<structs::_IMAGE_SECTION_HEADER> ptr_;
    std::string Name_;
};

} // namespace pe
} // namespace windows
} // namespace introvirt
