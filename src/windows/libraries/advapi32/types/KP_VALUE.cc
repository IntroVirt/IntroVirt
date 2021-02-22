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
#include <introvirt/windows/libraries/advapi32/types/KP_VALUE.hh>

namespace introvirt {
namespace windows {
namespace advapi32 {

const std::string& to_string(KP_VALUE value) {
    static const std::string KP_IV_STR("KP_IV");
    static const std::string KP_SALT_STR("KP_SALT");
    static const std::string KP_PADDING_STR("KP_PADDING");
    static const std::string KP_MODE_STR("KP_MODE");
    static const std::string KP_MODE_BITS_STR("KP_MODE_BITS");
    static const std::string KP_PERMISSIONS_STR("KP_PERMISSIONS");
    static const std::string KP_ALGID_STR("KP_ALGID");
    static const std::string KP_BLOCKLEN_STR("KP_BLOCKLEN");
    static const std::string KP_KEYLEN_STR("KP_KEYLEN");
    static const std::string KP_SALT_EX_STR("KP_SALT_EX");
    static const std::string KP_P_STR("KP_P");
    static const std::string KP_G_STR("KP_G");
    static const std::string KP_Q_STR("KP_Q");
    static const std::string KP_X_STR("KP_X");
    static const std::string KP_Y_STR("KP_Y");
    static const std::string KP_RA_STR("KP_RA");
    static const std::string KP_RB_STR("KP_RB");
    static const std::string KP_INFO_STR("KP_INFO");
    static const std::string KP_EFFECTIVE_KEYLEN_STR("KP_EFFECTIVE_KEYLEN");
    static const std::string KP_SCHANNEL_ALG_STR("KP_SCHANNEL_ALG");
    static const std::string KP_CLIENT_RANDOM_STR("KP_CLIENT_RANDOM");
    static const std::string KP_SERVER_RANDOM_STR("KP_SERVER_RANDOM");
    static const std::string KP_RP_STR("KP_RP");
    static const std::string KP_PRECOMP_MD5_STR("KP_PRECOMP_MD5");
    static const std::string KP_PRECOMP_SHA_STR("KP_PRECOMP_SHA");
    static const std::string KP_CERTIFICATE_STR("KP_CERTIFICATE");
    static const std::string KP_CLEAR_KEY_STR("KP_CLEAR_KEY");
    static const std::string KP_PUB_EX_LEN_STR("KP_PUB_EX_LEN");
    static const std::string KP_PUB_EX_VAL_STR("KP_PUB_EX_VAL");
    static const std::string KP_KEYVAL_STR("KP_KEYVAL");
    static const std::string KP_ADMIN_PIN_STR("KP_ADMIN_PIN");
    static const std::string KP_KEYEXCHANGE_PIN_STR("KP_KEYEXCHANGE_PIN");
    static const std::string KP_SIGNATURE_PIN_STR("KP_SIGNATURE_PIN");
    static const std::string KP_PREHASH_STR("KP_PREHASH");
    static const std::string KP_ROUNDS_STR("KP_ROUNDS");
    static const std::string KP_OAEP_PARAMS_STR("KP_OAEP_PARAMS");
    static const std::string KP_CMS_KEY_INFO_STR("KP_CMS_KEY_INFO");
    static const std::string KP_CMS_DH_KEY_INFO_STR("KP_CMS_DH_KEY_INFO");
    static const std::string KP_PUB_PARAMS_STR("KP_PUB_PARAMS");
    static const std::string KP_VERIFY_PARAMS_STR("KP_VERIFY_PARAMS");
    static const std::string KP_HIGHEST_VERSION_STR("KP_HIGHEST_VERSION");
    static const std::string KP_GET_USE_COUNT_STR("KP_GET_USE_COUNT");
    static const std::string KP_UNKNOWN_STR("UNKNOWN");

    switch (value) {
    case KP_VALUE::KP_IV:
        return KP_IV_STR;
    case KP_VALUE::KP_SALT:
        return KP_SALT_STR;
    case KP_VALUE::KP_PADDING:
        return KP_PADDING_STR;
    case KP_VALUE::KP_MODE:
        return KP_MODE_STR;
    case KP_VALUE::KP_MODE_BITS:
        return KP_MODE_BITS_STR;
    case KP_VALUE::KP_PERMISSIONS:
        return KP_PERMISSIONS_STR;
    case KP_VALUE::KP_ALGID:
        return KP_ALGID_STR;
    case KP_VALUE::KP_BLOCKLEN:
        return KP_BLOCKLEN_STR;
    case KP_VALUE::KP_KEYLEN:
        return KP_KEYLEN_STR;
    case KP_VALUE::KP_SALT_EX:
        return KP_SALT_EX_STR;
    case KP_VALUE::KP_P:
        return KP_P_STR;
    case KP_VALUE::KP_G:
        return KP_G_STR;
    case KP_VALUE::KP_Q:
        return KP_Q_STR;
    case KP_VALUE::KP_X:
        return KP_X_STR;
    case KP_VALUE::KP_Y:
        return KP_Y_STR;
    case KP_VALUE::KP_RA:
        return KP_RA_STR;
    case KP_VALUE::KP_RB:
        return KP_RB_STR;
    case KP_VALUE::KP_INFO:
        return KP_INFO_STR;
    case KP_VALUE::KP_EFFECTIVE_KEYLEN:
        return KP_EFFECTIVE_KEYLEN_STR;
    case KP_VALUE::KP_SCHANNEL_ALG:
        return KP_SCHANNEL_ALG_STR;
    case KP_VALUE::KP_CLIENT_RANDOM:
        return KP_CLIENT_RANDOM_STR;
    case KP_VALUE::KP_SERVER_RANDOM:
        return KP_SERVER_RANDOM_STR;
    case KP_VALUE::KP_RP:
        return KP_RP_STR;
    case KP_VALUE::KP_PRECOMP_MD5:
        return KP_PRECOMP_MD5_STR;
    case KP_VALUE::KP_PRECOMP_SHA:
        return KP_PRECOMP_SHA_STR;
    case KP_VALUE::KP_CERTIFICATE:
        return KP_CERTIFICATE_STR;
    case KP_VALUE::KP_CLEAR_KEY:
        return KP_CLEAR_KEY_STR;
    case KP_VALUE::KP_PUB_EX_LEN:
        return KP_PUB_EX_LEN_STR;
    case KP_VALUE::KP_PUB_EX_VAL:
        return KP_PUB_EX_VAL_STR;
    case KP_VALUE::KP_KEYVAL:
        return KP_KEYVAL_STR;
    case KP_VALUE::KP_ADMIN_PIN:
        return KP_ADMIN_PIN_STR;
    case KP_VALUE::KP_KEYEXCHANGE_PIN:
        return KP_KEYEXCHANGE_PIN_STR;
    case KP_VALUE::KP_SIGNATURE_PIN:
        return KP_SIGNATURE_PIN_STR;
    case KP_VALUE::KP_PREHASH:
        return KP_PREHASH_STR;
    case KP_VALUE::KP_ROUNDS:
        return KP_ROUNDS_STR;
    case KP_VALUE::KP_OAEP_PARAMS:
        return KP_OAEP_PARAMS_STR;
    case KP_VALUE::KP_CMS_KEY_INFO:
        return KP_CMS_KEY_INFO_STR;
    case KP_VALUE::KP_CMS_DH_KEY_INFO:
        return KP_CMS_DH_KEY_INFO_STR;
    case KP_VALUE::KP_PUB_PARAMS:
        return KP_PUB_PARAMS_STR;
    case KP_VALUE::KP_VERIFY_PARAMS:
        return KP_VERIFY_PARAMS_STR;
    case KP_VALUE::KP_HIGHEST_VERSION:
        return KP_HIGHEST_VERSION_STR;
    case KP_VALUE::KP_GET_USE_COUNT:
        return KP_GET_USE_COUNT_STR;
    }

    return KP_UNKNOWN_STR;
}

std::ostream& operator<<(std::ostream& os, KP_VALUE value) {
    os << to_string(value);
    return os;
}

} // namespace advapi32
} // namespace windows
} // namespace introvirt