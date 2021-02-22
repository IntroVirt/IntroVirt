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
#include <introvirt/windows/libraries/crypt32/functions/CryptDecodeMessage.hh>

#include <boost/io/ios_state.hpp>

namespace introvirt {
namespace windows {
namespace crypt32 {

/* Input arguments */
uint32_t CryptDecodeMessage::dwMsgTypeFlags() const { return dwMsgTypeFlags_; }
void CryptDecodeMessage::dwMsgTypeFlags(uint32_t dwMsgTypeFlags) {
    set_argument(0, dwMsgTypeFlags);
    dwMsgTypeFlags_ = dwMsgTypeFlags;
}

GuestVirtualAddress CryptDecodeMessage::pDecryptPara() const { return pDecryptPara_; }
void CryptDecodeMessage::pDecryptPara(const GuestVirtualAddress& gva) {
    set_address_argument(1, gva);
    pDecryptPara_ = gva;
    DecryptPara_.reset();
}

GuestVirtualAddress CryptDecodeMessage::pVerifyPara() const { return pVerifyPara_; }
void CryptDecodeMessage::pVerifyPara(const GuestVirtualAddress& gva) {
    set_address_argument(2, gva);
    pVerifyPara_ = gva;
    VerifyPara_.reset();
}

uint32_t CryptDecodeMessage::dwSignerIndex() const { return dwSignerIndex_; }
void CryptDecodeMessage::dwSignerIndex(uint32_t dwSignerIndex) {
    set_argument(3, dwSignerIndex);
    dwSignerIndex_ = dwSignerIndex;
}

GuestVirtualAddress CryptDecodeMessage::pbEncodedBlob() const { return pbEncodedBlob_; }
void CryptDecodeMessage::pbEncodedBlob(const GuestVirtualAddress& gva) {
    set_address_argument(4, gva);
    pbEncodedBlob_ = gva;
}

uint32_t CryptDecodeMessage::cbEncodedBlob() const { return cbEncodedBlob_; }
void CryptDecodeMessage::cbEncodedBlob(uint32_t cbEncodedBlob) {
    set_argument(5, cbEncodedBlob);
    cbEncodedBlob_ = cbEncodedBlob;
}

uint32_t CryptDecodeMessage::dwPrevInnerContentType() const { return dwPrevInnerContentType_; }
void CryptDecodeMessage::dwPrevInnerContentType(uint32_t dwPrevInnerContentType) {
    set_argument(6, dwPrevInnerContentType);
    dwPrevInnerContentType_ = dwPrevInnerContentType;
}

GuestVirtualAddress CryptDecodeMessage::pdwMsgType() const { return pdwMsgType_; }
void CryptDecodeMessage::pdwMsgType(const GuestVirtualAddress& gva) {
    set_address_argument(7, gva);
    pdwMsgType_ = gva;
}

GuestVirtualAddress CryptDecodeMessage::pdwInnerContentType() const { return pdwInnerContentType_; }
void CryptDecodeMessage::pdwInnerContentType(const GuestVirtualAddress& gva) {
    set_address_argument(8, gva);
    pdwInnerContentType_ = gva;
}

GuestVirtualAddress CryptDecodeMessage::pbDecoded() const { return pbDecoded_; }
void CryptDecodeMessage::pbDecoded(const GuestVirtualAddress& gva) {
    set_address_argument(9, gva);
    pbDecoded_ = gva;
}

GuestVirtualAddress CryptDecodeMessage::pcbDecoded() const { return pcbDecoded_; }
void CryptDecodeMessage::pcbDecoded(const GuestVirtualAddress& gva) {
    set_address_argument(10, gva);
    pcbDecoded_ = gva;
}

GuestVirtualAddress CryptDecodeMessage::ppXchgCert() const { return ppXchgCert_; }
void CryptDecodeMessage::ppXchgCert(const GuestVirtualAddress& gva) {
    set_address_argument(11, gva);
    ppXchgCert_ = gva;
}

GuestVirtualAddress CryptDecodeMessage::ppSignerCert() const { return ppSignerCert_; }
void CryptDecodeMessage::ppSignerCert(const GuestVirtualAddress& gva) {
    set_address_argument(12, gva);
    ppSignerCert_ = gva;
}

/* Helpers */
const CRYPT_DECRYPT_MESSAGE_PARA* CryptDecodeMessage::DecryptPara() const {
    if (!DecryptPara_ && pDecryptPara_) {
        DecryptPara_ = CRYPT_DECRYPT_MESSAGE_PARA::make_unique(pDecryptPara_, x64());
    }
    return DecryptPara_.get();
}
CRYPT_DECRYPT_MESSAGE_PARA* CryptDecodeMessage::DecryptPara() {
    const auto& const_this = this;
    return const_cast<CRYPT_DECRYPT_MESSAGE_PARA*>(const_this->DecryptPara());
}

const CRYPT_VERIFY_MESSAGE_PARA* CryptDecodeMessage::VerifyPara() const {
    if (!VerifyPara_ && pVerifyPara_) {
        VerifyPara_ = CRYPT_VERIFY_MESSAGE_PARA::make_unique(pDecryptPara_, x64());
    }
    return VerifyPara_.get();
}
CRYPT_VERIFY_MESSAGE_PARA* CryptDecodeMessage::VerifyPara() {
    const auto& const_this = this;
    return const_cast<CRYPT_VERIFY_MESSAGE_PARA*>(const_this->VerifyPara());
}

uint32_t CryptDecodeMessage::dwMsgType() const {
    if (pdwMsgType_)
        return *guest_ptr<uint32_t>(pdwMsgType_);

    // TODO: Should this throw an exception?
    return 0;
}
void CryptDecodeMessage::dwMsgType(uint32_t dwMsgType) {
    if (pdwMsgType_)
        *guest_ptr<uint32_t>(pdwMsgType_) = dwMsgType;

    // TODO: Should this throw an exception?
}

uint32_t CryptDecodeMessage::dwInnerContentType() const {
    if (pdwInnerContentType_)
        return *guest_ptr<uint32_t>(pdwInnerContentType_);

    // TODO: Should this throw an exception?
    return 0;
}
void CryptDecodeMessage::dwInnerContentType(uint32_t dwInnerContentType) {
    if (pdwInnerContentType_)
        *guest_ptr<uint32_t>(pdwInnerContentType_) = dwInnerContentType;

    // TODO: Should this throw an exception?
}

uint32_t CryptDecodeMessage::cbDecoded() const {
    if (pcbDecoded_)
        return *guest_ptr<uint32_t>(pcbDecoded_);

    // TODO: Should this throw an exception?
    return 0;
}
void CryptDecodeMessage::cbDecoded(uint32_t cbDecoded) {
    if (pcbDecoded_)
        *guest_ptr<uint32_t>(pcbDecoded_) = cbDecoded;
    // TODO: Should this throw an exception?
}

bool CryptDecodeMessage::result() const { return raw_return_value(); }

const std::string& CryptDecodeMessage::function_name() const { return FunctionName; }
const std::string& CryptDecodeMessage::library_name() const { return LibraryName; }
void CryptDecodeMessage::write(std::ostream& os) const {
    boost::io::ios_flags_saver ifs(os);
    // TODO
}

CryptDecodeMessage::CryptDecodeMessage(Event& event) : WindowsFunctionCall(event, ArgumentCount) {
    dwMsgTypeFlags_ = get_argument(0);
    pDecryptPara_ = get_address_argument(1);
    pVerifyPara_ = get_address_argument(2);
    dwSignerIndex_ = get_argument(3);
    pbEncodedBlob_ = get_address_argument(4);
    cbEncodedBlob_ = get_argument(5);
    dwPrevInnerContentType_ = get_argument(6);
    pdwMsgType_ = get_address_argument(7);
    pdwInnerContentType_ = get_address_argument(8);
    pbDecoded_ = get_address_argument(9);
    pcbDecoded_ = get_address_argument(10);
    ppXchgCert_ = get_address_argument(11);
    ppSignerCert_ = get_address_argument(12);
}

CryptDecodeMessage::~CryptDecodeMessage() = default;

} // namespace crypt32
} // namespace windows
} // namespace introvirt