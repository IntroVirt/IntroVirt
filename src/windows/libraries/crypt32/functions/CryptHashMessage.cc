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
#include <introvirt/windows/libraries/crypt32/functions/CryptHashMessage.hh>

#include <boost/io/ios_state.hpp>

namespace introvirt {
namespace windows {
namespace crypt32 {

/* Input arguments */
GuestVirtualAddress CryptHashMessage::pHashPara() const { return pHashPara_; }
void CryptHashMessage::pHashPara(const GuestVirtualAddress& gva) {
    set_address_argument(0, gva);
    pHashPara_ = gva;
}

bool CryptHashMessage::fDetachedHash() const { return fDetachedHash_; }
void CryptHashMessage::fDetachedHash(bool fDetachedHash) {
    set_argument(1, fDetachedHash);
    fDetachedHash_ = fDetachedHash;
}

uint32_t CryptHashMessage::cToBeHashed() const { return cToBeHashed_; }
void CryptHashMessage::cToBeHashed(uint32_t cToBeHashed) {
    set_argument(2, cToBeHashed_);
    cToBeHashed_ = cToBeHashed;
}

GuestVirtualAddress CryptHashMessage::prgpbToBeHashed() const { return prgpbToBeHashed_; }
void CryptHashMessage::prgpbToBeHashed(const GuestVirtualAddress& gva) {
    set_address_argument(3, gva);
    prgpbToBeHashed_ = gva;
}

GuestVirtualAddress CryptHashMessage::prgcbToBeHashed() const { return prgcbToBeHashed_; }
void CryptHashMessage::prgcbToBeHashed(const GuestVirtualAddress& gva) {
    set_address_argument(4, gva);
    prgcbToBeHashed_ = gva;
}

GuestVirtualAddress CryptHashMessage::pbHashedBlob() const { return pbHashedBlob_; }
void CryptHashMessage::pbHashedBlob(const GuestVirtualAddress& gva) {
    set_address_argument(5, gva);
    pbHashedBlob_ = gva;
}

GuestVirtualAddress CryptHashMessage::pcbHashedBlob() const { return pcbHashedBlob_; }
void CryptHashMessage::pcbHashedBlob(const GuestVirtualAddress& gva) {
    set_address_argument(6, gva);
    pcbHashedBlob_ = gva;
}

GuestVirtualAddress CryptHashMessage::pbComputedHash() const { return pbComputedHash_; }
void CryptHashMessage::pbComputedHash(const GuestVirtualAddress& gva) {
    set_address_argument(7, gva);
    pbComputedHash_ = gva;
}

GuestVirtualAddress CryptHashMessage::pcbComputedHash() const { return pcbComputedHash_; }
void CryptHashMessage::pcbComputedHash(const GuestVirtualAddress& gva) {
    set_address_argument(8, gva);
    pcbComputedHash_ = gva;
}

/* Helpers */
const CRYPT_HASH_MESSAGE_PARA* CryptHashMessage::HashPara() const {
    if (!HashPara_ && pHashPara_)
        HashPara_ = CRYPT_HASH_MESSAGE_PARA::make_unique(pHashPara_, x64());
    return HashPara_.get();
}
CRYPT_HASH_MESSAGE_PARA* CryptHashMessage::HashPara() {
    const auto* const_this = this;
    return const_cast<CRYPT_HASH_MESSAGE_PARA*>(const_this->HashPara());
}

bool CryptHashMessage::result() const { return raw_return_value(); }

const std::string& CryptHashMessage::function_name() const { return FunctionName; }
const std::string& CryptHashMessage::library_name() const { return LibraryName; }
void CryptHashMessage::write(std::ostream& os) const {
    boost::io::ios_flags_saver ifs(os);
    // TODO
}

CryptHashMessage::CryptHashMessage(Event& event) : WindowsFunctionCall(event, ArgumentCount) {
    pHashPara_ = get_address_argument(0);
    fDetachedHash_ = get_argument(1);
    cToBeHashed_ = get_argument(2);
    prgpbToBeHashed_ = get_address_argument(3);
    prgcbToBeHashed_ = get_address_argument(4);
    pbHashedBlob_ = get_address_argument(5);
    pcbHashedBlob_ = get_address_argument(6);
    pbComputedHash_ = get_address_argument(7);
    pcbComputedHash_ = get_address_argument(8);
}

CryptHashMessage::~CryptHashMessage() = default;

} // namespace crypt32
} // namespace windows
} // namespace introvirt