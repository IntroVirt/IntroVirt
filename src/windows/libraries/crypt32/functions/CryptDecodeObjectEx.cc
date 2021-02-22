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
#include <introvirt/core/memory/guest_ptr.hh>
#include <introvirt/windows/libraries/crypt32/functions/CryptDecodeObjectEx.hh>

#include <boost/io/ios_state.hpp>

namespace introvirt {
namespace windows {
namespace crypt32 {

/* Input arguments */
uint32_t CryptDecodeObjectEx::dwCertEncodingType() const { return dwCertEncodingType_; }
void CryptDecodeObjectEx::dwCertEncodingType(uint32_t dwCertEncodingType) {
    set_argument(0, dwCertEncodingType);
    dwCertEncodingType_ = dwCertEncodingType;
}

CryptStructType CryptDecodeObjectEx::StructType() const {
    uint64_t ptrval = lpszStructType_.value();
    if (ptrval <= 0xFFFF)
        return static_cast<CryptStructType>(ptrval);
    return CryptStructType::CRYPT_ENCODE_DECODE_NONE;
}
void CryptDecodeObjectEx::StructType(CryptStructType type) {
    set_argument(1, type);
    lpszStructType_ = static_cast<uint64_t>(type);
}

GuestVirtualAddress CryptDecodeObjectEx::lpszStructType() const {
    uint64_t ptrval = lpszStructType_.value();
    if (ptrval <= 0xFFFF)
        return NullGuestAddress();
    return lpszStructType_;
}

void CryptDecodeObjectEx::lpszStructType(const GuestVirtualAddress& gva) {
    set_address_argument(1, gva);
    lpszStructType_ = gva;
}

GuestVirtualAddress CryptDecodeObjectEx::pbEncoded() const { return pbEncoded_; }
void CryptDecodeObjectEx::pbEncoded(const GuestVirtualAddress& gva) {
    set_address_argument(2, gva);
    pbEncoded_ = gva;
}

uint32_t CryptDecodeObjectEx::cbEncoded() const { return cbEncoded_; }
void CryptDecodeObjectEx::cbEncoded(uint32_t cbEncoded) {
    set_argument(3, cbEncoded);
    cbEncoded_ = cbEncoded;
}

uint32_t CryptDecodeObjectEx::dwFlags() const { return dwFlags_; }
void CryptDecodeObjectEx::dwFlags(uint32_t dwFlags) {
    set_argument(4, dwFlags);
    dwFlags_ = dwFlags;
}

GuestVirtualAddress CryptDecodeObjectEx::pDecodePara() const { return pDecodePara_; }
void CryptDecodeObjectEx::pDecodePara(const GuestVirtualAddress& gva) {
    set_address_argument(5, gva);
    pDecodePara_ = gva;
    DecodePara_.reset();
}

GuestVirtualAddress CryptDecodeObjectEx::pvStructInfo() const { return pvStructInfo_; }
void CryptDecodeObjectEx::pvStructInfo(const GuestVirtualAddress& gva) {
    set_address_argument(6, gva);
    pvStructInfo_ = gva;
}

GuestVirtualAddress CryptDecodeObjectEx::pcbStructInfo() const { return pcbStructInfo_; }
void CryptDecodeObjectEx::pcbStructInfo(const GuestVirtualAddress& gva) {
    set_address_argument(7, gva);
    pcbStructInfo_ = gva;
}

/* Helpers */
std::string CryptDecodeObjectEx::szStructType() const {
    uint64_t ptrval = lpszStructType_.value();
    if (ptrval <= 0xFFFF) {
        return to_string(static_cast<CryptStructType>(ptrval));
    }

    auto mapping = map_guest_cstr(lpszStructType_);
    return std::string(mapping.get(), mapping.length());
}

const CRYPT_DECODE_PARA* CryptDecodeObjectEx::DecodePara() const {
    if (!DecodePara_ && pDecodePara_) {
        DecodePara_ = CRYPT_DECODE_PARA::make_unique(pDecodePara_, x64());
    }
    return DecodePara_.get();
}
CRYPT_DECODE_PARA* CryptDecodeObjectEx::DecodePara() {
    const auto* const_this = this;
    return const_cast<CRYPT_DECODE_PARA*>(const_this->DecodePara());
}

uint32_t CryptDecodeObjectEx::cbStructInfo() const {
    if (pcbStructInfo_) {
        return *guest_ptr<uint32_t>(pcbStructInfo_);
    }
    // TODO: Throw an exception ?
    return 0;
}
void CryptDecodeObjectEx::cbStructInfo(uint32_t cbStructInfo) {
    if (pcbStructInfo_) {
        *guest_ptr<uint32_t>(pcbStructInfo_) = cbStructInfo;
    } else {
        // TODO: Throw an exception ?
    }
}

bool CryptDecodeObjectEx::result() const { return raw_return_value(); }

const std::string& CryptDecodeObjectEx::function_name() const { return FunctionName; }
const std::string& CryptDecodeObjectEx::library_name() const { return LibraryName; }
void CryptDecodeObjectEx::write(std::ostream& os) const {
    boost::io::ios_flags_saver ifs(os);
    // TODO
}

CryptDecodeObjectEx::CryptDecodeObjectEx(Event& event) : WindowsFunctionCall(event, ArgumentCount) {
    dwCertEncodingType_ = get_argument(0);
    lpszStructType_ = get_address_argument(1);
    pbEncoded_ = get_address_argument(2);
    cbEncoded_ = get_argument(3);
    dwFlags_ = get_argument(4);
    pDecodePara_ = get_address_argument(5);
    pvStructInfo_ = get_address_argument(6);
    pcbStructInfo_ = get_address_argument(7);
}

CryptDecodeObjectEx::~CryptDecodeObjectEx() = default;

} // namespace crypt32
} // namespace windows
} // namespace introvirt