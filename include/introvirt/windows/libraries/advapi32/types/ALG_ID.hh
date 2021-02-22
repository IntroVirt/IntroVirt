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

#include <ostream>
#include <string>

namespace introvirt {
namespace windows {
namespace advapi32 {

/**
 * @brief Encryption algoritm for advapi32 calls
 *
 * @see https://docs.microsoft.com/en-us/windows/win32/seccrypto/alg-id
 *
 */
enum ALG_ID : uint32_t {
    CALG_3DES = 0x00006603,
    CALG_3DES_112 = 0x00006609,
    CALG_AES = 0x00006611,
    CALG_AES_128 = 0x0000660e,
    CALG_AES_192 = 0x0000660f,
    CALG_AES_256 = 0x00006610,
    CALG_AGREEDKEY_ANY = 0x0000aa03,
    CALG_CYLINK_MEK = 0x0000660c,
    CALG_DES = 0x00006601,
    CALG_DESX = 0x00006604,
    CALG_DH_EPHEM = 0x0000aa02,
    CALG_DH_SF = 0x0000aa01,
    CALG_DSS_SIGN = 0x00002200,
    CALG_ECDH = 0x0000aa05,
    CALG_ECDH_EPHEM = 0x0000ae06,
    CALG_ECDSA = 0x00002203,
    CALG_ECMQV = 0x0000a001,
    CALG_HASH_REPLACE_OWF = 0x0000800b,
    CALG_HUGHES_MD5 = 0x0000a003,
    CALG_HMAC = 0x00008009,
    CALG_KEA_KEYX = 0x0000aa04,
    CALG_MAC = 0x00008005,
    CALG_MD2 = 0x00008001,
    CALG_MD4 = 0x00008002,
    CALG_MD5 = 0x00008003,
    CALG_NO_SIGN = 0x00002000,
    CALG_OID_INFO_CNG_ONLY = 0xffffffff,
    CALG_OID_INFO_PARAMETERS = 0xfffffffe,
    CALG_PCT1_MASTER = 0x00004c04,
    CALG_RC2 = 0x00006602,
    CALG_RC4 = 0x00006801,
    CALG_RC5 = 0x0000660d,
    CALG_RSA_KEYX = 0x0000a400,
    CALG_RSA_SIGN = 0x00002400,
    CALG_SCHANNEL_ENC_KEY = 0x00004c07,
    CALG_SCHANNEL_MAC_KEY = 0x00004c03,
    CALG_SCHANNEL_MASTER_HASH = 0x00004c02,
    CALG_SEAL = 0x00006802,
    CALG_SHA1 = 0x00008004,
    CALG_SHA_256 = 0x0000800c,
    CALG_SHA_384 = 0x0000800d,
    CALG_SHA_512 = 0x0000800e,
    CALG_SKIPJACK = 0x0000660a,
    CALG_SSL2_MASTER = 0x00004c05,
    CALG_SSL3_MASTER = 0x00004c01,
    CALG_SSL3_SHAMD5 = 0x00008008,
    CALG_TEK = 0x0000660b,
    CALG_TLS1_MASTER = 0x00004c06,
    CALG_TLS1PRF = 0x0000800a,
};

const std::string& to_string(ALG_ID);
std::ostream& operator<<(std::ostream&, ALG_ID);

} // namespace advapi32
} // namespace windows
} // namespace introvirt