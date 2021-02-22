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
#include <introvirt/windows/libraries/advapi32/types/BLOB.hh>
#include <introvirt/windows/libraries/advapi32/types/types.hh>

#include "structs.hh"

namespace introvirt {
namespace windows {
namespace advapi32 {

BLOB_TYPE BLOB::bType() const { return reinterpret_cast<const _BLOBHEADER*>(header_.get())->bType; }

uint8_t BLOB::bVersion() const {
    return reinterpret_cast<const _BLOBHEADER*>(header_.get())->bVersion;
}
ALG_ID BLOB::aiKeyAlg() const {
    return reinterpret_cast<const _BLOBHEADER*>(header_.get())->aiKeyAlg;
}

BLOB::BLOB(const GuestVirtualAddress& gva, uint32_t length) {
    if (unlikely(length < sizeof(_BLOBHEADER)))
        throw BufferTooSmallException(sizeof(_BLOBHEADER), length);

    header_.reset(gva, length);
}

BLOB::~BLOB() = default;

} // namespace advapi32
} // namespace windows
} // namespace introvirt