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
#include <introvirt/windows/common/Utf16String.hh>
#include <introvirt/windows/pe/types/FILE_INFO.hh>

#include <cstdint>

namespace introvirt {
namespace windows {
namespace pe {

inline static guest_ptr<void> dword_align(const guest_ptr<void>& ptr) {
    if ((ptr.address() & 0x3) != 0u) {
        return ptr.clone((ptr.address() + 4) & 0xFFFFFFFFFFFFFFFCLL);
    }
    return ptr;
}

namespace structs {

struct _FILE_INFO {
    uint16_t wLength;
    uint16_t wValueLength;
    uint16_t wType;
    char16_t szKey[];

    // Children follow after szKey on a dword-aligned boundary
};

} // namespace structs

/**
 * @brief Helper class for VS_VERSIONINFO and children
 *
 */
template <typename _BaseClass = FILE_INFO>
class FILE_INFO_IMPL : public _BaseClass {
  public:
    inline uint16_t wLength() const override { return ptr_->wLength; }
    inline uint16_t wValueLength() const override { return ptr_->wValueLength; }
    inline uint16_t wType() const override { return ptr_->wType; }
    inline const std::string& szKey() const override { return szKey_; }
    inline guest_ptr<void> pChildren() const override { return pChildren_; }

    FILE_INFO_IMPL(const guest_ptr<void>& ptr) : ptr_(ptr) {
        const guest_ptr<void> pszKey(ptr + offsetof(structs::_FILE_INFO, szKey));
        szKey_ = map_guest_wstring(pszKey).str();

        // Make sure to include the null terminator as part of the offset
        pChildren_ = dword_align(pszKey + sizeof(uint16_t) + (szKey_.length() * sizeof(char16_t)));
    }

  private:
    guest_ptr<structs::_FILE_INFO> ptr_;
    std::string szKey_;
    guest_ptr<void> pChildren_;
};

} // namespace pe
} // namespace windows
} // namespace introvirt