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
#include <introvirt/windows/pe/exception/PeException.hh>
#include <introvirt/windows/pe/types/DOS_HEADER.hh>

#include <optional>

namespace introvirt {
namespace windows {
namespace pe {

namespace structs {

struct _DOS_HEADER {
    uint16_t e_magic;     // offset   0x0 size   0x2
    uint16_t e_cblp;      // offset   0x2 size   0x2
    uint16_t e_cp;        // offset   0x4 size   0x2
    uint16_t e_crlc;      // offset   0x6 size   0x2
    uint16_t e_cparhdr;   // offset   0x8 size   0x2
    uint16_t e_minalloc;  // offset   0xa size   0x2
    uint16_t e_maxalloc;  // offset   0xc size   0x2
    uint16_t e_ss;        // offset   0xe size   0x2
    uint16_t e_sp;        // offset  0x10 size   0x2
    uint16_t e_csum;      // offset  0x12 size   0x2
    uint16_t e_ip;        // offset  0x14 size   0x2
    uint16_t e_cs;        // offset  0x16 size   0x2
    uint16_t e_lfarlc;    // offset  0x18 size   0x2
    uint16_t e_ovno;      // offset  0x1a size   0x2
    uint16_t e_res[0x4];  // offset  0x1c size   0x8
    uint16_t e_oemid;     // offset  0x24 size   0x2
    uint16_t e_oeminfo;   // offset  0x26 size   0x2
    uint16_t e_res2[0xa]; // offset  0x28 size  0x14
    int32_t e_lfanew;     // offset  0x3c size   0x4
} __attribute__((aligned(4)));

} // namespace structs

class DOS_HEADER_IMPL final : public DOS_HEADER {
  public:
    inline auto e_lfanew() const { return data_->e_lfanew; }

    DOS_HEADER_IMPL(const GuestVirtualAddress& image_base_address) : data_(image_base_address) {

        // Validate the signature is "MZ"
        if (unlikely(data_->e_magic != 0x5a4D))
            throw PeException("Invalid DOS Header");
    }

  private:
    guest_ptr<structs::_DOS_HEADER> data_;
};

} // namespace pe
} // namespace windows
} // namespace introvirt