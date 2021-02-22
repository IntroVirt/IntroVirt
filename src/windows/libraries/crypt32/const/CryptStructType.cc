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
#include <introvirt/windows/libraries/crypt32/const/CryptStructType.hh>

namespace introvirt {
namespace windows {
namespace crypt32 {

static const std::string CRYPT_ENCODE_DECODE_NONE_STR("CRYPT_ENCODE_DECODE_NONE");
static const std::string X509_CERT_STR("X509_CERT");
static const std::string X509_CERT_TO_BE_SIGNED_STR("X509_CERT_TO_BE_SIGNED");
static const std::string X509_CERT_CRL_TO_BE_SIGNED_STR("X509_CERT_CRL_TO_BE_SIGNED");
static const std::string X509_CERT_REQUEST_TO_BE_SIGNED_STR("X509_CERT_REQUEST_TO_BE_SIGNED");
static const std::string X509_EXTENSIONS_STR("X509_EXTENSIONS");
static const std::string X509_NAME_VALUE_STR("X509_NAME_VALUE");
static const std::string X509_NAME_STR("X509_NAME");
static const std::string X509_PUBLIC_KEY_INFO_STR("X509_PUBLIC_KEY_INFO");
static const std::string X509_AUTHORITY_KEY_ID_STR("X509_AUTHORITY_KEY_ID");
static const std::string X509_KEY_ATTRIBUTES_STR("X509_KEY_ATTRIBUTES");
static const std::string X509_KEY_USAGE_RESTRICTION_STR("X509_KEY_USAGE_RESTRICTION");
static const std::string X509_ALTERNATE_NAME_STR("X509_ALTERNATE_NAME");
static const std::string X509_BASIC_CONSTRAINTS_STR("X509_BASIC_CONSTRAINTS");
static const std::string X509_KEY_USAGE_STR("X509_KEY_USAGE");
static const std::string X509_BASIC_CONSTRAINTS2_STR("X509_BASIC_CONSTRAINTS2");
static const std::string X509_CERT_POLICIES_STR("X509_CERT_POLICIES");
static const std::string PKCS_UTC_TIME_STR("PKCS_UTC_TIME");
static const std::string PKCS_TIME_REQUEST_STR("PKCS_TIME_REQUEST");
static const std::string RSA_CSP_PUBLICKEYBLOB_STR("RSA_CSP_PUBLICKEYBLOB");
static const std::string X509_UNICODE_NAME_STR("X509_UNICODE_NAME");
static const std::string X509_KEYGEN_REQUEST_TO_BE_SIGNED_STR("X509_KEYGEN_REQUEST_TO_BE_SIGNED");
static const std::string PKCS_ATTRIBUTE_STR("PKCS_ATTRIBUTE");
static const std::string PKCS_CONTENT_INFO_SEQUENCE_OF_ANY_STR("PKCS_CONTENT_INFO_SEQUENCE_OF_ANY");
static const std::string X509_UNICODE_NAME_VALUE_STR("X509_UNICODE_NAME_VALUE");
static const std::string X509_OCTET_STRING_STR("X509_OCTET_STRING");
static const std::string X509_BITS_STR("X509_BITS");
static const std::string X509_INTEGER_STR("X509_INTEGER");
static const std::string X509_MULTI_BYTE_INTEGER_STR("X509_MULTI_BYTE_INTEGER");
static const std::string X509_ENUMERATED_STR("X509_ENUMERATED");
static const std::string X509_CHOICE_OF_TIME_STR("X509_CHOICE_OF_TIME");
static const std::string X509_AUTHORITY_KEY_ID2_STR("X509_AUTHORITY_KEY_ID2");
static const std::string X509_AUTHORITY_INFO_ACCESS_STR("X509_AUTHORITY_INFO_ACCESS");
static const std::string PKCS_CONTENT_INFO_STR("PKCS_CONTENT_INFO");
static const std::string X509_SEQUENCE_OF_ANY_STR("X509_SEQUENCE_OF_ANY");
static const std::string X509_CRL_DIST_POINTS_STR("X509_CRL_DIST_POINTS");
static const std::string X509_ENHANCED_KEY_USAGE_STR("X509_ENHANCED_KEY_USAGE");
static const std::string PKCS_CTL_STR("PKCS_CTL");
static const std::string X509_MULTI_BYTE_UINT_STR("X509_MULTI_BYTE_UINT");
static const std::string X509_DSS_PARAMETERS_STR("X509_DSS_PARAMETERS");
static const std::string X509_DSS_SIGNATURE_STR("X509_DSS_SIGNATURE");
static const std::string PKCS_RC2_CBC_PARAMETERS_STR("PKCS_RC2_CBC_PARAMETERS");
static const std::string PKCS_SMIME_CAPABILITIES_STR("PKCS_SMIME_CAPABILITIES");
static const std::string PKCS_RSA_PRIVATE_KEY_STR("PKCS_RSA_PRIVATE_KEY");
static const std::string PKCS_PRIVATE_KEY_INFO_STR("PKCS_PRIVATE_KEY_INFO");
static const std::string PKCS_ENCRYPTED_PRIVATE_KEY_INFO_STR("PKCS_ENCRYPTED_PRIVATE_KEY_INFO");
static const std::string
    X509_PKIX_POLICY_QUALIFIER_USERNOTICE_STR("X509_PKIX_POLICY_QUALIFIER_USERNOTICE");
static const std::string X509_DH_PARAMETERS_STR("X509_DH_PARAMETERS");
static const std::string PKCS_ATTRIBUTES_STR("PKCS_ATTRIBUTES");
static const std::string PKCS_SORTED_CTL_STR("PKCS_SORTED_CTL");
static const std::string X942_DH_PARAMETERS_STR("X942_DH_PARAMETERS");
static const std::string X509_BITS_WITHOUT_TRAILING_ZEROES_STR("X509_BITS_WITHOUT_TRAILING_ZEROES");
static const std::string X942_OTHER_INFO_STR("X942_OTHER_INFO");
static const std::string X509_CERT_PAIR_STR("X509_CERT_PAIR");
static const std::string X509_ISSUING_DIST_POINT_STR("X509_ISSUING_DIST_POINT");
static const std::string X509_NAME_CONSTRAINTS_STR("X509_NAME_CONSTRAINTS");
static const std::string X509_POLICY_MAPPINGS_STR("X509_POLICY_MAPPINGS");
static const std::string X509_POLICY_CONSTRAINTS_STR("X509_POLICY_CONSTRAINTS");
static const std::string X509_CROSS_CERT_DIST_POINTS_STR("X509_CROSS_CERT_DIST_POINTS");
static const std::string CMC_DATA_STR("CMC_DATA");
static const std::string CMC_RESPONSE_STR("CMC_RESPONSE");
static const std::string CMC_STATUS_STR("CMC_STATUS");
static const std::string CMC_ADD_EXTENSIONS_STR("CMC_ADD_EXTENSIONS");
static const std::string CMC_ADD_ATTRIBUTES_STR("CMC_ADD_ATTRIBUTES");
static const std::string X509_CERTIFICATE_TEMPLATE_STR("X509_CERTIFICATE_TEMPLATE");
static const std::string OCSP_SIGNED_REQUEST_STR("OCSP_SIGNED_REQUEST");
static const std::string OCSP_REQUEST_STR("OCSP_REQUEST");
static const std::string OCSP_RESPONSE_STR("OCSP_RESPONSE");
static const std::string OCSP_BASIC_SIGNED_RESPONSE_STR("OCSP_BASIC_SIGNED_RESPONSE");
static const std::string OCSP_BASIC_RESPONSE_STR("OCSP_BASIC_RESPONSE");
static const std::string X509_LOGOTYPE_EXT_STR("X509_LOGOTYPE_EXT");
static const std::string X509_BIOMETRIC_EXT_STR("X509_BIOMETRIC_EXT");
static const std::string CNG_RSA_PUBLIC_KEY_BLOB_STR("CNG_RSA_PUBLIC_KEY_BLOB");
static const std::string X509_OBJECT_IDENTIFIER_STR("X509_OBJECT_IDENTIFIER");
static const std::string X509_ALGORITHM_IDENTIFIER_STR("X509_ALGORITHM_IDENTIFIER");
static const std::string PKCS_RSA_SSA_PSS_PARAMETERS_STR("PKCS_RSA_SSA_PSS_PARAMETERS");
static const std::string PKCS_RSAES_OAEP_PARAMETERS_STR("PKCS_RSAES_OAEP_PARAMETERS");
static const std::string ECC_CMS_SHARED_INFO_STR("ECC_CMS_SHARED_INFO");
static const std::string PKCS7_SIGNER_INFO_STR("PKCS7_SIGNER_INFO");
static const std::string CMS_SIGNER_INFO_STR("CMS_SIGNER_INFO");
static const std::string UNKNOWN_STR("UNKNOWN");

std::string to_string(CryptStructType type) {
    switch (type) {
    case CryptStructType::CRYPT_ENCODE_DECODE_NONE:
        return CRYPT_ENCODE_DECODE_NONE_STR;
    case CryptStructType::X509_CERT:
        return X509_CERT_STR;
    case CryptStructType::X509_CERT_TO_BE_SIGNED:
        return X509_CERT_TO_BE_SIGNED_STR;
    case CryptStructType::X509_CERT_CRL_TO_BE_SIGNED:
        return X509_CERT_CRL_TO_BE_SIGNED_STR;
    case CryptStructType::X509_CERT_REQUEST_TO_BE_SIGNED:
        return X509_CERT_REQUEST_TO_BE_SIGNED_STR;
    case CryptStructType::X509_EXTENSIONS:
        return X509_EXTENSIONS_STR;
    case CryptStructType::X509_NAME_VALUE:
        return X509_NAME_VALUE_STR;
    case CryptStructType::X509_NAME:
        return X509_NAME_STR;
    case CryptStructType::X509_PUBLIC_KEY_INFO:
        return X509_PUBLIC_KEY_INFO_STR;
    case CryptStructType::X509_AUTHORITY_KEY_ID:
        return X509_AUTHORITY_KEY_ID_STR;
    case CryptStructType::X509_KEY_ATTRIBUTES:
        return X509_KEY_ATTRIBUTES_STR;
    case CryptStructType::X509_KEY_USAGE_RESTRICTION:
        return X509_KEY_USAGE_RESTRICTION_STR;
    case CryptStructType::X509_ALTERNATE_NAME:
        return X509_ALTERNATE_NAME_STR;
    case CryptStructType::X509_BASIC_CONSTRAINTS:
        return X509_BASIC_CONSTRAINTS_STR;
    case CryptStructType::X509_KEY_USAGE:
        return X509_KEY_USAGE_STR;
    case CryptStructType::X509_BASIC_CONSTRAINTS2:
        return X509_BASIC_CONSTRAINTS2_STR;
    case CryptStructType::X509_CERT_POLICIES:
        return X509_CERT_POLICIES_STR;
    case CryptStructType::PKCS_UTC_TIME:
        return PKCS_UTC_TIME_STR;
    case CryptStructType::PKCS_TIME_REQUEST:
        return PKCS_TIME_REQUEST_STR;
    case CryptStructType::RSA_CSP_PUBLICKEYBLOB:
        return RSA_CSP_PUBLICKEYBLOB_STR;
    case CryptStructType::X509_UNICODE_NAME:
        return X509_UNICODE_NAME_STR;
    case CryptStructType::X509_KEYGEN_REQUEST_TO_BE_SIGNED:
        return X509_KEYGEN_REQUEST_TO_BE_SIGNED_STR;
    case CryptStructType::PKCS_ATTRIBUTE:
        return PKCS_ATTRIBUTE_STR;
    case CryptStructType::PKCS_CONTENT_INFO_SEQUENCE_OF_ANY:
        return PKCS_CONTENT_INFO_SEQUENCE_OF_ANY_STR;
    case CryptStructType::X509_UNICODE_NAME_VALUE:
        return X509_UNICODE_NAME_VALUE_STR;
    case CryptStructType::X509_OCTET_STRING:
        return X509_OCTET_STRING_STR;
    case CryptStructType::X509_BITS:
        return X509_BITS_STR;
    case CryptStructType::X509_INTEGER:
        return X509_INTEGER_STR;
    case CryptStructType::X509_MULTI_BYTE_INTEGER:
        return X509_MULTI_BYTE_INTEGER_STR;
    case CryptStructType::X509_ENUMERATED:
        return X509_ENUMERATED_STR;
    case CryptStructType::X509_CHOICE_OF_TIME:
        return X509_CHOICE_OF_TIME_STR;
    case CryptStructType::X509_AUTHORITY_KEY_ID2:
        return X509_AUTHORITY_KEY_ID2_STR;
    case CryptStructType::X509_AUTHORITY_INFO_ACCESS:
        return X509_AUTHORITY_INFO_ACCESS_STR;
    case CryptStructType::PKCS_CONTENT_INFO:
        return PKCS_CONTENT_INFO_STR;
    case CryptStructType::X509_SEQUENCE_OF_ANY:
        return X509_SEQUENCE_OF_ANY_STR;
    case CryptStructType::X509_CRL_DIST_POINTS:
        return X509_CRL_DIST_POINTS_STR;
    case CryptStructType::X509_ENHANCED_KEY_USAGE:
        return X509_ENHANCED_KEY_USAGE_STR;
    case CryptStructType::PKCS_CTL:
        return PKCS_CTL_STR;
    case CryptStructType::X509_MULTI_BYTE_UINT:
        return X509_MULTI_BYTE_UINT_STR;
    case CryptStructType::X509_DSS_PARAMETERS:
        return X509_DSS_PARAMETERS_STR;
    case CryptStructType::X509_DSS_SIGNATURE:
        return X509_DSS_SIGNATURE_STR;
    case CryptStructType::PKCS_RC2_CBC_PARAMETERS:
        return PKCS_RC2_CBC_PARAMETERS_STR;
    case CryptStructType::PKCS_SMIME_CAPABILITIES:
        return PKCS_SMIME_CAPABILITIES_STR;
    case CryptStructType::PKCS_RSA_PRIVATE_KEY:
        return PKCS_RSA_PRIVATE_KEY_STR;
    case CryptStructType::PKCS_PRIVATE_KEY_INFO:
        return PKCS_PRIVATE_KEY_INFO_STR;
    case CryptStructType::PKCS_ENCRYPTED_PRIVATE_KEY_INFO:
        return PKCS_ENCRYPTED_PRIVATE_KEY_INFO_STR;
    case CryptStructType::X509_PKIX_POLICY_QUALIFIER_USERNOTICE:
        return X509_PKIX_POLICY_QUALIFIER_USERNOTICE_STR;
    case CryptStructType::X509_DH_PARAMETERS:
        return X509_DH_PARAMETERS_STR;
    case CryptStructType::PKCS_ATTRIBUTES:
        return PKCS_ATTRIBUTES_STR;
    case CryptStructType::PKCS_SORTED_CTL:
        return PKCS_SORTED_CTL_STR;
    case CryptStructType::X942_DH_PARAMETERS:
        return X942_DH_PARAMETERS_STR;
    case CryptStructType::X509_BITS_WITHOUT_TRAILING_ZEROES:
        return X509_BITS_WITHOUT_TRAILING_ZEROES_STR;
    case CryptStructType::X942_OTHER_INFO:
        return X942_OTHER_INFO_STR;
    case CryptStructType::X509_CERT_PAIR:
        return X509_CERT_PAIR_STR;
    case CryptStructType::X509_ISSUING_DIST_POINT:
        return X509_ISSUING_DIST_POINT_STR;
    case CryptStructType::X509_NAME_CONSTRAINTS:
        return X509_NAME_CONSTRAINTS_STR;
    case CryptStructType::X509_POLICY_MAPPINGS:
        return X509_POLICY_MAPPINGS_STR;
    case CryptStructType::X509_POLICY_CONSTRAINTS:
        return X509_POLICY_CONSTRAINTS_STR;
    case CryptStructType::X509_CROSS_CERT_DIST_POINTS:
        return X509_CROSS_CERT_DIST_POINTS_STR;
    case CryptStructType::CMC_DATA:
        return CMC_DATA_STR;
    case CryptStructType::CMC_RESPONSE:
        return CMC_RESPONSE_STR;
    case CryptStructType::CMC_STATUS:
        return CMC_STATUS_STR;
    case CryptStructType::CMC_ADD_EXTENSIONS:
        return CMC_ADD_EXTENSIONS_STR;
    case CryptStructType::CMC_ADD_ATTRIBUTES:
        return CMC_ADD_ATTRIBUTES_STR;
    case CryptStructType::X509_CERTIFICATE_TEMPLATE:
        return X509_CERTIFICATE_TEMPLATE_STR;
    case CryptStructType::OCSP_SIGNED_REQUEST:
        return OCSP_SIGNED_REQUEST_STR;
    case CryptStructType::OCSP_REQUEST:
        return OCSP_REQUEST_STR;
    case CryptStructType::OCSP_RESPONSE:
        return OCSP_RESPONSE_STR;
    case CryptStructType::OCSP_BASIC_SIGNED_RESPONSE:
        return OCSP_BASIC_SIGNED_RESPONSE_STR;
    case CryptStructType::OCSP_BASIC_RESPONSE:
        return OCSP_BASIC_RESPONSE_STR;
    case CryptStructType::X509_LOGOTYPE_EXT:
        return X509_LOGOTYPE_EXT_STR;
    case CryptStructType::X509_BIOMETRIC_EXT:
        return X509_BIOMETRIC_EXT_STR;
    case CryptStructType::CNG_RSA_PUBLIC_KEY_BLOB:
        return CNG_RSA_PUBLIC_KEY_BLOB_STR;
    case CryptStructType::X509_OBJECT_IDENTIFIER:
        return X509_OBJECT_IDENTIFIER_STR;
    case CryptStructType::X509_ALGORITHM_IDENTIFIER:
        return X509_ALGORITHM_IDENTIFIER_STR;
    case CryptStructType::PKCS_RSA_SSA_PSS_PARAMETERS:
        return PKCS_RSA_SSA_PSS_PARAMETERS_STR;
    case CryptStructType::PKCS_RSAES_OAEP_PARAMETERS:
        return PKCS_RSAES_OAEP_PARAMETERS_STR;
    case CryptStructType::ECC_CMS_SHARED_INFO:
        return ECC_CMS_SHARED_INFO_STR;
    case CryptStructType::PKCS7_SIGNER_INFO:
        return PKCS7_SIGNER_INFO_STR;
    case CryptStructType::CMS_SIGNER_INFO:
        return CMS_SIGNER_INFO_STR;
    }
    return UNKNOWN_STR;
}

std::ostream& operator<<(std::ostream& os, CryptStructType& type) {
    os << to_string(type);
    return os;
}

} // namespace crypt32
} // namespace windows
} // namespace introvirt