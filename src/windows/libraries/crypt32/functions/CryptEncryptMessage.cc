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
#include <introvirt/windows/libraries/crypt32/functions/CryptEncryptMessage.hh>

#include <boost/io/ios_state.hpp>

namespace introvirt {
namespace windows {
namespace crypt32 {

/* Input arguments */

GuestVirtualAddress CryptEncryptMessage::pEncryptPara() const { return pEncryptPara_; }
void CryptEncryptMessage::pEncryptPara(const GuestVirtualAddress& gva) {
    set_address_argument(0, gva);
    pEncryptPara_ = gva;
    EncryptPara_.reset();
}

uint32_t CryptEncryptMessage::cRecipientCert() const { return cRecipientCert_; }
void CryptEncryptMessage::cRecipientCert(uint32_t cRecipientCert) {
    set_argument(1, cRecipientCert);
    cRecipientCert_ = cRecipientCert;
}

GuestVirtualAddress CryptEncryptMessage::prgpRecipientCert() const { return prgpRecipientCert_; }
void CryptEncryptMessage::prgpRecipientCert(const GuestVirtualAddress& gva) {
    set_address_argument(2, gva);
    prgpRecipientCert_ = gva;
}

GuestVirtualAddress CryptEncryptMessage::pbToBeEncrypted() const { return pbToBeEncrypted_; }
void CryptEncryptMessage::pbToBeEncrypted(const GuestVirtualAddress& gva) {
    set_address_argument(3, gva);
    pbToBeEncrypted_ = gva;
}

uint32_t CryptEncryptMessage::cbToBeEncrypted() const { return cbToBeEncrypted_; }
void CryptEncryptMessage::cbToBeEncrypted(uint32_t cbToBeEncrypted) {
    set_argument(4, cbToBeEncrypted);
    cbToBeEncrypted_ = cbToBeEncrypted;
}

GuestVirtualAddress CryptEncryptMessage::pbEncryptedBlob() const { return pbEncryptedBlob_; }
void CryptEncryptMessage::pbEncryptedBlob(const GuestVirtualAddress& gva) {
    set_address_argument(5, gva);
    pbEncryptedBlob_ = gva;
}

GuestVirtualAddress CryptEncryptMessage::pcbEncryptedBlob() const { return pcbEncryptedBlob_; }
void CryptEncryptMessage::pcbEncryptedBlob(const GuestVirtualAddress& gva) {
    set_address_argument(6, gva);
    pcbEncryptedBlob_ = gva;
}

/* Helpers */
const CRYPT_DECRYPT_MESSAGE_PARA* CryptEncryptMessage::EncryptPara() const {
    if (!EncryptPara_ && pEncryptPara_) {
        EncryptPara_ = CRYPT_DECRYPT_MESSAGE_PARA::make_unique(pEncryptPara_, x64());
    }
    return EncryptPara_.get();
}
CRYPT_DECRYPT_MESSAGE_PARA* CryptEncryptMessage::EncryptPara() {
    const auto* const_this = this;
    return const_cast<CRYPT_DECRYPT_MESSAGE_PARA*>(const_this->EncryptPara());
}

uint32_t CryptEncryptMessage::cbEncryptedBlob() const {
    if (pcbEncryptedBlob_) {
        return *guest_ptr<uint32_t>(pcbEncryptedBlob_);
    }
    // TODO: Throw an exception ?
    return 0;
}
void CryptEncryptMessage::cbEncryptedBlob(uint32_t cbEncryptedBlob) {
    if (pcbEncryptedBlob_) {
        *guest_ptr<uint32_t>(pcbEncryptedBlob_) = cbEncryptedBlob;
    } else {
        // TODO: Throw an exception ?
    }
}

bool CryptEncryptMessage::result() const { return raw_return_value(); }

const std::string& CryptEncryptMessage::function_name() const { return FunctionName; }
const std::string& CryptEncryptMessage::library_name() const { return LibraryName; }
void CryptEncryptMessage::write(std::ostream& os) const {
    boost::io::ios_flags_saver ifs(os);
    // TODO
}

CryptEncryptMessage::CryptEncryptMessage(Event& event) : WindowsFunctionCall(event, ArgumentCount) {
    pEncryptPara_ = get_address_argument(0);
    cRecipientCert_ = get_argument(1);
    prgpRecipientCert_ = get_address_argument(2);
    pbToBeEncrypted_ = get_address_argument(3);
    cbToBeEncrypted_ = get_argument(4);
    pbEncryptedBlob_ = get_address_argument(5);
    pcbEncryptedBlob_ = get_address_argument(6);
}

CryptEncryptMessage::~CryptEncryptMessage() = default;

} // namespace crypt32
} // namespace windows
} // namespace introvirt