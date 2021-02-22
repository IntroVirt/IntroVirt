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
#include <introvirt/windows/libraries/advapi32/types/ALG_ID.hh>

namespace introvirt {
namespace windows {
namespace advapi32 {

const std::string& to_string(ALG_ID id) {
    static const std::string CALG_3DES_STR("CALG_3DES");
    static const std::string CALG_3DES_112_STR("CALG_3DES_112");
    static const std::string CALG_AES_STR("CALG_AES");
    static const std::string CALG_AES_128_STR("CALG_AES_128");
    static const std::string CALG_AES_192_STR("CALG_AES_192");
    static const std::string CALG_AES_256_STR("CALG_AES_256");
    static const std::string CALG_AGREEDKEY_ANY_STR("CALG_AGREEDKEY_ANY");
    static const std::string CALG_CYLINK_MEK_STR("CALG_CYLINK_MEK");
    static const std::string CALG_DES_STR("CALG_DES");
    static const std::string CALG_DESX_STR("CALG_DESX");
    static const std::string CALG_DH_EPHEM_STR("CALG_DH_EPHEM");
    static const std::string CALG_DH_SF_STR("CALG_DH_SF");
    static const std::string CALG_DSS_SIGN_STR("CALG_DSS_SIGN");
    static const std::string CALG_ECDH_STR("CALG_ECDH");
    static const std::string CALG_ECDH_EPHEM_STR("CALG_ECDH_EPHEM");
    static const std::string CALG_ECDSA_STR("CALG_ECDSA");
    static const std::string CALG_ECMQV_STR("CALG_ECMQV");
    static const std::string CALG_HASH_REPLACE_OWF_STR("CALG_HASH_REPLACE_OWF");
    static const std::string CALG_HUGHES_MD5_STR("CALG_HUGHES_MD5");
    static const std::string CALG_HMAC_STR("CALG_HMAC");
    static const std::string CALG_KEA_KEYX_STR("CALG_KEA_KEYX");
    static const std::string CALG_MAC_STR("CALG_MAC");
    static const std::string CALG_MD2_STR("CALG_MD2");
    static const std::string CALG_MD4_STR("CALG_MD4");
    static const std::string CALG_MD5_STR("CALG_MD5");
    static const std::string CALG_NO_SIGN_STR("CALG_NO_SIGN");
    static const std::string CALG_OID_INFO_CNG_ONLY_STR("CALG_OID_INFO_CNG_ONLY");
    static const std::string CALG_OID_INFO_PARAMETERS_STR("CALG_OID_INFO_PARAMETERS");
    static const std::string CALG_PCT1_MASTER_STR("CALG_PCT1_MASTER");
    static const std::string CALG_RC2_STR("CALG_RC2");
    static const std::string CALG_RC4_STR("CALG_RC4");
    static const std::string CALG_RC5_STR("CALG_RC5");
    static const std::string CALG_RSA_KEYX_STR("CALG_RSA_KEYX");
    static const std::string CALG_RSA_SIGN_STR("CALG_RSA_SIGN");
    static const std::string CALG_SCHANNEL_ENC_KEY_STR("CALG_SCHANNEL_ENC_KEY");
    static const std::string CALG_SCHANNEL_MAC_KEY_STR("CALG_SCHANNEL_MAC_KEY");
    static const std::string CALG_SCHANNEL_MASTER_HASH_STR("CALG_SCHANNEL_MASTER_HASH");
    static const std::string CALG_SEAL_STR("CALG_SEAL");
    static const std::string CALG_SHA_STR("CALG_SHA");
    static const std::string CALG_SHA1_STR("CALG_SHA1");
    static const std::string CALG_SHA_256_STR("CALG_SHA_256");
    static const std::string CALG_SHA_384_STR("CALG_SHA_384");
    static const std::string CALG_SHA_512_STR("CALG_SHA_512");
    static const std::string CALG_SKIPJACK_STR("CALG_SKIPJACK");
    static const std::string CALG_SSL2_MASTER_STR("CALG_SSL2_MASTER");
    static const std::string CALG_SSL3_MASTER_STR("CALG_SSL3_MASTER");
    static const std::string CALG_SSL3_SHAMD5_STR("CALG_SSL3_SHAMD5");
    static const std::string CALG_TEK_STR("CALG_TEK");
    static const std::string CALG_TLS1_MASTER_STR("CALG_TLS1_MASTER");
    static const std::string CALG_TLS1PRF_STR("CALG_TLS1PRF");
    static const std::string CALG_UNKNOWN_STR("CALG_UNKNOWN");

    switch (id) {
    case ALG_ID::CALG_3DES:
        return CALG_3DES_STR;
    case ALG_ID::CALG_3DES_112:
        return CALG_3DES_112_STR;
    case ALG_ID::CALG_AES:
        return CALG_AES_STR;
    case ALG_ID::CALG_AES_128:
        return CALG_AES_128_STR;
    case ALG_ID::CALG_AES_192:
        return CALG_AES_192_STR;
    case ALG_ID::CALG_AES_256:
        return CALG_AES_256_STR;
    case ALG_ID::CALG_AGREEDKEY_ANY:
        return CALG_AGREEDKEY_ANY_STR;
    case ALG_ID::CALG_CYLINK_MEK:
        return CALG_CYLINK_MEK_STR;
    case ALG_ID::CALG_DES:
        return CALG_DES_STR;
    case ALG_ID::CALG_DESX:
        return CALG_DESX_STR;
    case ALG_ID::CALG_DH_EPHEM:
        return CALG_DH_EPHEM_STR;
    case ALG_ID::CALG_DH_SF:
        return CALG_DH_SF_STR;
    case ALG_ID::CALG_DSS_SIGN:
        return CALG_DSS_SIGN_STR;
    case ALG_ID::CALG_ECDH:
        return CALG_ECDH_STR;
    case ALG_ID::CALG_ECDH_EPHEM:
        return CALG_ECDH_EPHEM_STR;
    case ALG_ID::CALG_ECDSA:
        return CALG_ECDSA_STR;
    case ALG_ID::CALG_ECMQV:
        return CALG_ECMQV_STR;
    case ALG_ID::CALG_HASH_REPLACE_OWF:
        return CALG_HASH_REPLACE_OWF_STR;
    case ALG_ID::CALG_HUGHES_MD5:
        return CALG_HUGHES_MD5_STR;
    case ALG_ID::CALG_HMAC:
        return CALG_HMAC_STR;
    case ALG_ID::CALG_KEA_KEYX:
        return CALG_KEA_KEYX_STR;
    case ALG_ID::CALG_MAC:
        return CALG_MAC_STR;
    case ALG_ID::CALG_MD2:
        return CALG_MD2_STR;
    case ALG_ID::CALG_MD4:
        return CALG_MD4_STR;
    case ALG_ID::CALG_MD5:
        return CALG_MD5_STR;
    case ALG_ID::CALG_NO_SIGN:
        return CALG_NO_SIGN_STR;
    case ALG_ID::CALG_OID_INFO_CNG_ONLY:
        return CALG_OID_INFO_CNG_ONLY_STR;
    case ALG_ID::CALG_OID_INFO_PARAMETERS:
        return CALG_OID_INFO_PARAMETERS_STR;
    case ALG_ID::CALG_PCT1_MASTER:
        return CALG_PCT1_MASTER_STR;
    case ALG_ID::CALG_RC2:
        return CALG_RC2_STR;
    case ALG_ID::CALG_RC4:
        return CALG_RC4_STR;
    case ALG_ID::CALG_RC5:
        return CALG_RC5_STR;
    case ALG_ID::CALG_RSA_KEYX:
        return CALG_RSA_KEYX_STR;
    case ALG_ID::CALG_RSA_SIGN:
        return CALG_RSA_SIGN_STR;
    case ALG_ID::CALG_SCHANNEL_ENC_KEY:
        return CALG_SCHANNEL_ENC_KEY_STR;
    case ALG_ID::CALG_SCHANNEL_MAC_KEY:
        return CALG_SCHANNEL_MAC_KEY_STR;
    case ALG_ID::CALG_SCHANNEL_MASTER_HASH:
        return CALG_SCHANNEL_MASTER_HASH_STR;
    case ALG_ID::CALG_SEAL:
        return CALG_SEAL_STR;
    case ALG_ID::CALG_SHA1:
        return CALG_SHA1_STR;
    case ALG_ID::CALG_SHA_256:
        return CALG_SHA_256_STR;
    case ALG_ID::CALG_SHA_384:
        return CALG_SHA_384_STR;
    case ALG_ID::CALG_SHA_512:
        return CALG_SHA_512_STR;
    case ALG_ID::CALG_SKIPJACK:
        return CALG_SKIPJACK_STR;
    case ALG_ID::CALG_SSL2_MASTER:
        return CALG_SSL2_MASTER_STR;
    case ALG_ID::CALG_SSL3_MASTER:
        return CALG_SSL3_MASTER_STR;
    case ALG_ID::CALG_SSL3_SHAMD5:
        return CALG_SSL3_SHAMD5_STR;
    case ALG_ID::CALG_TEK:
        return CALG_TEK_STR;
    case ALG_ID::CALG_TLS1_MASTER:
        return CALG_TLS1_MASTER_STR;
    case ALG_ID::CALG_TLS1PRF:
        return CALG_TLS1PRF_STR;
    }

    return CALG_UNKNOWN_STR;
}

std::ostream& operator<<(std::ostream& os, ALG_ID id) {
    os << to_string(id);
    return os;
}

} // namespace advapi32
} // namespace windows
} // namespace introvirt