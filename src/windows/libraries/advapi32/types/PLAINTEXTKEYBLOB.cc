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
#include <introvirt/core/exception/BufferTooSmallException.hh>
#include <introvirt/util/compiler.hh>
#include <introvirt/windows/libraries/advapi32/types/PLAINTEXTKEYBLOB.hh>
#include <introvirt/windows/libraries/advapi32/types/types.hh>

#include "structs.hh"

namespace introvirt {
namespace windows {
namespace advapi32 {

guest_ptr<const uint8_t[]> PLAINTEXTKEYBLOB::KeyData() const { return key_data_; }

PLAINTEXTKEYBLOB::PLAINTEXTKEYBLOB(const GuestVirtualAddress& gva, uint32_t length)
    : BLOB(gva, length) {

    // Validate some lengths
    if (unlikely(length < sizeof(_PLAINTEXTKEYBLOB)))
        throw BufferTooSmallException(sizeof(_PLAINTEXTKEYBLOB), length);

    const auto* header = reinterpret_cast<const _PLAINTEXTKEYBLOB*>(header_.get());

    length -= sizeof(_PLAINTEXTKEYBLOB);
    if (unlikely(length < header->dwKeySize))
        throw BufferTooSmallException(sizeof(_PLAINTEXTKEYBLOB), length);

    // Map in the key data
    key_data_.reset(gva + offsetof(_PLAINTEXTKEYBLOB, rgbKeyData), header->dwKeySize);
}

} // namespace advapi32
} // namespace windows
} // namespace introvirt