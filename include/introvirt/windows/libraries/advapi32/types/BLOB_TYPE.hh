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

#include <cstdint>
#include <ostream>
#include <string>

namespace introvirt {
namespace windows {
namespace advapi32 {

enum BLOB_TYPE : uint8_t {
    SIMPLEBLOB = 1,
    PUBLICKEYBLOB = 6,
    PRIVATEKEYBLOB = 7,
    PLAINTEXTKEYBLOB = 8,
    OPAQUEKEYBLOB = 9,
    PUBLICKEYBLOBEX = 10,
    SYMMETRICWRAPKEYBLOB = 11,
};

const std::string& to_string(BLOB_TYPE value);
std::ostream& operator<<(std::ostream&, BLOB_TYPE);

} // namespace advapi32
} // namespace windows
} // namespace introvirt