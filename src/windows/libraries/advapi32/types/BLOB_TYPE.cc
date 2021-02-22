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
#include <introvirt/windows/libraries/advapi32/types/BLOB_TYPE.hh>

namespace introvirt {
namespace windows {
namespace advapi32 {

const std::string& to_string(BLOB_TYPE value) {
    static const std::string SIMPLEBLOB_STR("SIMPLEBLOB");
    static const std::string PUBLICKEYBLOB_STR("PUBLICKEYBLOB");
    static const std::string PRIVATEKEYBLOB_STR("PRIVATEKEYBLOB");
    static const std::string PLAINTEXTKEYBLOB_STR("PLAINTEXTKEYBLOB");
    static const std::string OPAQUEKEYBLOB_STR("OPAQUEKEYBLOB");
    static const std::string PUBLICKEYBLOBEX_STR("PUBLICKEYBLOBEX");
    static const std::string SYMMETRICWRAPKEYBLOB_STR("SYMMETRICWRAPKEYBLOB");
    static const std::string UNKNOWNBLOB_STR("UNKNOWN");

    switch (value) {
    case BLOB_TYPE::SIMPLEBLOB:
        return SIMPLEBLOB_STR;
    case BLOB_TYPE::PUBLICKEYBLOB:
        return PUBLICKEYBLOB_STR;
    case BLOB_TYPE::PRIVATEKEYBLOB:
        return PRIVATEKEYBLOB_STR;
    case BLOB_TYPE::PLAINTEXTKEYBLOB:
        return PLAINTEXTKEYBLOB_STR;
    case BLOB_TYPE::OPAQUEKEYBLOB:
        return OPAQUEKEYBLOB_STR;
    case BLOB_TYPE::PUBLICKEYBLOBEX:
        return PUBLICKEYBLOBEX_STR;
    case BLOB_TYPE::SYMMETRICWRAPKEYBLOB:
        return SYMMETRICWRAPKEYBLOB_STR;
    }

    return UNKNOWNBLOB_STR;
};

std::ostream& operator<<(std::ostream& os, BLOB_TYPE value) {
    os << to_string(value);
    return os;
}

} // namespace advapi32
} // namespace windows
} // namespace introvirt