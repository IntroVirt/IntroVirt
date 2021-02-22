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
#include "IMAGE_RESOURCE_DIRECTORY_ENTRY_IMPL.hh"

#include <introvirt/windows/common/Utf16String.hh>

namespace introvirt {
namespace windows {
namespace pe {

IMAGE_RESOURCE_DIRECTORY_ENTRY_IMPL::IMAGE_RESOURCE_DIRECTORY_ENTRY_IMPL(
    const GuestVirtualAddress& pImageBase, const GuestVirtualAddress& pResourceSection,
    const GuestVirtualAddress& pResourceEntry)
    : data_(pResourceEntry) {

    if (NameIsString()) {
        // Get the string length and convert to the length in bytes
        const GuestVirtualAddress pStrLen = pResourceSection + data_->NameOffset;

        // This is the number of char16_ts, not bytes.
        const uint16_t strLen = *guest_ptr<uint16_t>(pStrLen);

        if (strLen > 0) {
            // TODO: This doesn't look right. The string is at the same address as the length?
            Name_ = Utf16String::convert(
                guest_ptr<char16_t[]>(pResourceSection + data_->NameOffset + 2, strLen));
        }
    }

    if (DataIsDirectory()) {
        const GuestVirtualAddress pDirectory = pResourceSection + data_->OffsetToDirectory;
        directory_.emplace(pImageBase, pResourceSection, pDirectory);
    } else {
        const GuestVirtualAddress pData = pResourceSection + data_->OffsetToData;
        data_entry_.emplace(pImageBase, pData);
    }
}

} // namespace pe
} // namespace windows
} // namespace introvirt