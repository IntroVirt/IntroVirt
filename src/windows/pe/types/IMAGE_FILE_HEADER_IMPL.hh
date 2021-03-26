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

#include "DOS_HEADER_IMPL.hh"

#include <introvirt/core/memory/guest_ptr.hh>
#include <introvirt/windows/pe/types/IMAGE_FILE_HEADER.hh>

namespace introvirt {
namespace windows {
namespace pe {

namespace structs {

struct _IMAGE_FILE_HEADER {
    int32_t Signature;
    MachineType Machine;           // offset   0x0 size   0x2
    uint16_t NumberOfSections;     // offset   0x2 size   0x2
    uint32_t TimeDateStamp;        // offset   0x4 size   0x4
    uint32_t PointerToSymbolTable; // offset   0x8 size   0x4
    uint32_t NumberOfSymbols;      // offset   0xc size   0x4
    uint16_t SizeOfOptionalHeader; // offset  0x10 size   0x2
    uint16_t Characteristics;      // offset  0x12 size   0x2
} __attribute__((aligned(4)));

} // namespace structs

class IMAGE_FILE_HEADER_IMPL final : public IMAGE_FILE_HEADER {
  public:
    MachineType Machine() const override { return ptr_->Machine; }
    uint16_t NumberOfSections() const override { return ptr_->NumberOfSections; }
    uint32_t TimeDateStamp() const override { return ptr_->TimeDateStamp; }
    uint32_t PointerToSymbolTable() const override { return ptr_->PointerToSymbolTable; }
    uint32_t NumberOfSymbols() const override { return ptr_->NumberOfSymbols; }
    uint16_t SizeOfOptionalHeader() const override { return ptr_->SizeOfOptionalHeader; }
    uint16_t Characteristics() const override { return ptr_->Characteristics; }

    guest_ptr<void> ptr() const { return ptr_; }

    IMAGE_FILE_HEADER_IMPL(const guest_ptr<void>& image_base, const DOS_HEADER_IMPL& dos_header)
        : ptr_(image_base + dos_header.e_lfanew()) {
        if (unlikely(ptr_->Signature != 0x4550)) // 0x4550 == "PE\0\0"
            throw PeException("Bad PE signature");
    }

  private:
    const guest_ptr<structs::_IMAGE_FILE_HEADER> ptr_;
};

} // namespace pe
} // namespace windows
} // namespace introvirt
