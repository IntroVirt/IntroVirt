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
namespace crypt32 {

enum CryptStructType {
    CRYPT_ENCODE_DECODE_NONE = 0,
    X509_CERT = 1,
    X509_CERT_TO_BE_SIGNED = 2,
    X509_CERT_CRL_TO_BE_SIGNED = 3,
    X509_CERT_REQUEST_TO_BE_SIGNED = 4,
    X509_EXTENSIONS = 5,
    X509_NAME_VALUE = 6,
    X509_NAME = 7,
    X509_PUBLIC_KEY_INFO = 8,
    X509_AUTHORITY_KEY_ID = 9,
    X509_KEY_ATTRIBUTES = 10,
    X509_KEY_USAGE_RESTRICTION = 11,
    X509_ALTERNATE_NAME = 12,
    X509_BASIC_CONSTRAINTS = 13,
    X509_KEY_USAGE = 14,
    X509_BASIC_CONSTRAINTS2 = 15,
    X509_CERT_POLICIES = 16,
    PKCS_UTC_TIME = 17,
    PKCS_TIME_REQUEST = 18,
    RSA_CSP_PUBLICKEYBLOB = 19,
    X509_UNICODE_NAME = 20,
    X509_KEYGEN_REQUEST_TO_BE_SIGNED = 21,
    PKCS_ATTRIBUTE = 22,
    PKCS_CONTENT_INFO_SEQUENCE_OF_ANY = 23,
    X509_UNICODE_NAME_VALUE = 24,
    X509_ANY_STRING = X509_NAME_VALUE,
    X509_UNICODE_ANY_STRING = X509_UNICODE_NAME_VALUE,
    X509_OCTET_STRING = 25,
    X509_BITS = 26,
    X509_INTEGER = 27,
    X509_MULTI_BYTE_INTEGER = 28,
    X509_ENUMERATED = 29,
    X509_CHOICE_OF_TIME = 30,
    X509_AUTHORITY_KEY_ID2 = 31,
    X509_AUTHORITY_INFO_ACCESS = 32,
    X509_CRL_REASON_CODE = X509_ENUMERATED,
    PKCS_CONTENT_INFO = 33,
    X509_SEQUENCE_OF_ANY = 34,
    X509_CRL_DIST_POINTS = 35,
    X509_ENHANCED_KEY_USAGE = 36,
    PKCS_CTL = 37,
    X509_MULTI_BYTE_UINT = 38,
    X509_DSS_PUBLICKEY = X509_MULTI_BYTE_UINT,
    X509_DSS_PARAMETERS = 39,
    X509_DSS_SIGNATURE = 40,
    PKCS_RC2_CBC_PARAMETERS = 41,
    PKCS_SMIME_CAPABILITIES = 42,
    PKCS_RSA_PRIVATE_KEY = 43,
    PKCS_PRIVATE_KEY_INFO = 44,
    PKCS_ENCRYPTED_PRIVATE_KEY_INFO = 45,
    X509_PKIX_POLICY_QUALIFIER_USERNOTICE = 46,
    X509_DH_PUBLICKEY = X509_MULTI_BYTE_UINT,
    X509_DH_PARAMETERS = 47,
    PKCS_ATTRIBUTES = 48,
    PKCS_SORTED_CTL = 49,
    X509_ECC_SIGNATURE = 47,
    X942_DH_PARAMETERS = 50,
    X509_BITS_WITHOUT_TRAILING_ZEROES = 51,
    X942_OTHER_INFO = 52,
    X509_CERT_PAIR = 53,
    X509_ISSUING_DIST_POINT = 54,
    X509_NAME_CONSTRAINTS = 55,
    X509_POLICY_MAPPINGS = 56,
    X509_POLICY_CONSTRAINTS = 57,
    X509_CROSS_CERT_DIST_POINTS = 58,
    CMC_DATA = 59,
    CMC_RESPONSE = 60,
    CMC_STATUS = 61,
    CMC_ADD_EXTENSIONS = 62,
    CMC_ADD_ATTRIBUTES = 63,
    X509_CERTIFICATE_TEMPLATE = 64,
    OCSP_SIGNED_REQUEST = 65,
    OCSP_REQUEST = 66,
    OCSP_RESPONSE = 67,
    OCSP_BASIC_SIGNED_RESPONSE = 68,
    OCSP_BASIC_RESPONSE = 69,
    X509_LOGOTYPE_EXT = 70,
    X509_BIOMETRIC_EXT = 71,
    CNG_RSA_PUBLIC_KEY_BLOB = 72,
    X509_OBJECT_IDENTIFIER = 73,
    X509_ALGORITHM_IDENTIFIER = 74,
    PKCS_RSA_SSA_PSS_PARAMETERS = 75,
    PKCS_RSAES_OAEP_PARAMETERS = 76,
    ECC_CMS_SHARED_INFO = 77,
    PKCS7_SIGNER_INFO = 500,
    CMS_SIGNER_INFO = 501,
};

std::string to_string(CryptStructType type);
std::ostream& operator<<(std::ostream& os, CryptStructType& type);

} // namespace crypt32
} // namespace windows
} // namespace introvirt