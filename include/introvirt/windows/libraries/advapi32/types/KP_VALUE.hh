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

enum KP_VALUE : uint32_t {
    KP_IV = 1,
    KP_SALT = 2,
    KP_PADDING = 3,
    KP_MODE = 4,
    KP_MODE_BITS = 5,
    KP_PERMISSIONS = 6,
    KP_ALGID = 7,
    KP_BLOCKLEN = 8,
    KP_KEYLEN = 9,
    KP_SALT_EX = 10,
    KP_P = 11,
    KP_G = 12,
    KP_Q = 13,
    KP_X = 14,
    KP_Y = 15,
    KP_RA = 16,
    KP_RB = 17,
    KP_INFO = 18,
    KP_EFFECTIVE_KEYLEN = 19,
    KP_SCHANNEL_ALG = 20,
    KP_CLIENT_RANDOM = 21,
    KP_SERVER_RANDOM = 22,
    KP_RP = 23,
    KP_PRECOMP_MD5 = 24,
    KP_PRECOMP_SHA = 25,
    KP_CERTIFICATE = 26,
    KP_CLEAR_KEY = 27,
    KP_PUB_EX_LEN = 28,
    KP_PUB_EX_VAL = 29,
    KP_KEYVAL = 30,
    KP_ADMIN_PIN = 31,
    KP_KEYEXCHANGE_PIN = 32,
    KP_SIGNATURE_PIN = 33,
    KP_PREHASH = 34,
    KP_ROUNDS = 35,
    KP_OAEP_PARAMS = 36,
    KP_CMS_KEY_INFO = 37,
    KP_CMS_DH_KEY_INFO = 38,
    KP_PUB_PARAMS = 39,
    KP_VERIFY_PARAMS = 40,
    KP_HIGHEST_VERSION = 41,
    KP_GET_USE_COUNT = 42,
};

const std::string& to_string(KP_VALUE value);
std::ostream& operator<<(std::ostream&, KP_VALUE);

} // namespace advapi32
} // namespace windows
} // namespace introvirt