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

#include "FILE_INFO_IMPL.hh"

#include <introvirt/core/memory/GuestVirtualAddress.hh>
#include <introvirt/windows/common/WStr.hh>
#include <introvirt/windows/pe/types/StringTable.hh>

#include <string>

namespace introvirt {
namespace windows {
namespace pe {

class StringTableImpl final : public FILE_INFO_IMPL<StringTable> {
  public:
    uint16_t language_identifier() const override { return language_id_; }
    uint16_t code_page() const override { return code_page_; }

    const std::map<std::string, std::string>& entries() const override { return entries_; }

    StringTableImpl(const GuestVirtualAddress& pStringTable)
        : FILE_INFO_IMPL<StringTable>(pStringTable) {

        // The Key UNICODE_STRING holds an 8-digit hex number
        // Get it and convert it to a number
        const uint32_t dwKey = std::stoul(szKey(), nullptr, 16);

        // The 4 most significant *digits* are the language identifier
        language_id_ = dwKey >> 16;

        // The four least significant digits are the code page
        code_page_ = dwKey & 0xFFFF;

        GuestVirtualAddress pChildren = this->pChildren();
        GuestVirtualAddress pEndChildren = pChildren + (wLength() - (pChildren - pStringTable));

        while (pChildren < pEndChildren) {
            FILE_INFO_IMPL<> fi(pChildren);
            entries_.try_emplace(fi.szKey(), Utf16String::convert(map_guest_wstr(fi.pChildren())));
            pChildren = dword_align(pChildren + fi.wLength());
        }
    }

  public:
    uint16_t language_id_;
    uint16_t code_page_;
    std::map<std::string, std::string> entries_;
};

} /* namespace pe */
} /* namespace windows */
} /* namespace introvirt */
