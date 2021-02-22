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

#include <introvirt/windows/libraries/advapi32/types/types.hh>

namespace introvirt {
namespace windows {
namespace advapi32 {

struct _BLOBHEADER {
    BLOB_TYPE bType;
    uint8_t bVersion;
    uint16_t reserved;
    ALG_ID aiKeyAlg;
};

struct _PLAINTEXTKEYBLOB {
    struct _BLOBHEADER hdr;
    uint32_t dwKeySize;
    uint8_t rgbKeyData[];
};

} // namespace advapi32
} // namespace windows
} // namespace introvirt