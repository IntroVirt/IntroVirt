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
#include <introvirt/windows/libraries/crypt32/functions/CryptDecryptMessage.hh>

#include <boost/io/ios_state.hpp>

namespace introvirt {
namespace windows {
namespace crypt32 {

/* Input arguments */

GuestVirtualAddress CryptDecryptMessage::pDecryptPara() const { return pDecryptPara_; }
void CryptDecryptMessage::pDecryptPara(const GuestVirtualAddress& gva) {
    set_address_argument(0, gva);
    pDecryptPara_ = gva;
    DecryptPara_.reset();
}

GuestVirtualAddress CryptDecryptMessage::pbEncryptedBlob() const { return pbEncryptedBlob_; }
void CryptDecryptMessage::pbEncryptedBlob(const GuestVirtualAddress& gva) {
    set_address_argument(1, gva);
    pbEncryptedBlob_ = gva;
}

uint32_t CryptDecryptMessage::cbEncryptedBlob() const { return cbEncryptedBlob_; }
void CryptDecryptMessage::cbEncryptedBlob(uint32_t cbEncryptedBlob) {
    set_argument(2, cbEncryptedBlob);
    cbEncryptedBlob_ = cbEncryptedBlob;
}

GuestVirtualAddress CryptDecryptMessage::pbDecrypted() const { return pbDecrypted_; }
void CryptDecryptMessage::pbDecrypted(const GuestVirtualAddress& gva) {
    set_address_argument(3, gva);
    pbDecrypted_ = gva;
}

GuestVirtualAddress CryptDecryptMessage::ppXchgCert() const { return ppXchgCert_; }
void CryptDecryptMessage::ppXchgCert(const GuestVirtualAddress& gva) {
    set_address_argument(4, gva);
    ppXchgCert_ = gva;
}

GuestVirtualAddress CryptDecryptMessage::pcbDecrypted() const { return pcbDecrypted_; }
void CryptDecryptMessage::pcbDecrypted(const GuestVirtualAddress& gva) {
    set_address_argument(5, gva);
    pcbDecrypted_ = gva;
}

/* Helpers */
const CRYPT_DECRYPT_MESSAGE_PARA* CryptDecryptMessage::DecryptPara() const {
    if (!DecryptPara_ && pDecryptPara_) {
        DecryptPara_ = CRYPT_DECRYPT_MESSAGE_PARA::make_unique(pDecryptPara_, x64());
    }
    return DecryptPara_.get();
}
CRYPT_DECRYPT_MESSAGE_PARA* CryptDecryptMessage::DecryptPara() {
    const auto* const_this = this;
    return const_cast<CRYPT_DECRYPT_MESSAGE_PARA*>(const_this->DecryptPara());
}

uint32_t CryptDecryptMessage::cbDecrypted() const {
    if (pcbDecrypted_) {
        return *guest_ptr<uint32_t>(pcbDecrypted_);
    }
    // TODO: Throw an exception ?
    return 0;
}
void CryptDecryptMessage::cbDecrypted(uint32_t cbDecrypted) {
    if (pcbDecrypted_) {
        *guest_ptr<uint32_t>(pcbDecrypted_) = cbDecrypted;
    } else {
        // TODO: Throw an exception ?
    }
}

bool CryptDecryptMessage::result() const { return raw_return_value(); }

const std::string& CryptDecryptMessage::function_name() const { return FunctionName; }
const std::string& CryptDecryptMessage::library_name() const { return LibraryName; }
void CryptDecryptMessage::write(std::ostream& os) const {
    boost::io::ios_flags_saver ifs(os);
    // TODO
}

CryptDecryptMessage::CryptDecryptMessage(Event& event) : WindowsFunctionCall(event, ArgumentCount) {
    pDecryptPara_ = get_address_argument(0);
    pbEncryptedBlob_ = get_address_argument(1);
    cbEncryptedBlob_ = get_argument(2);
    pbDecrypted_ = get_address_argument(3);
    pcbDecrypted_ = get_address_argument(4);
    ppXchgCert_ = get_address_argument(5);
}

CryptDecryptMessage::~CryptDecryptMessage() = default;

} // namespace crypt32
} // namespace windows
} // namespace introvirt