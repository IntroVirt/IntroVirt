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
#include <introvirt/windows/libraries/crypt32/functions/CryptUnprotectData.hh>

#include <boost/io/ios_state.hpp>

namespace introvirt {
namespace windows {
namespace crypt32 {

/* Input arguments */
GuestVirtualAddress CryptUnprotectData::pDataIn() const { return pDataIn_; }
void CryptUnprotectData::pDataIn(const GuestVirtualAddress& value) {
    set_address_argument(0, value);
    pDataIn_ = value;
}

GuestVirtualAddress CryptUnprotectData::ppszDataDescr() const { return ppszDataDescr_; }
void CryptUnprotectData::ppszDataDescr(const GuestVirtualAddress& value) {
    set_address_argument(1, value);
    ppszDataDescr_ = value;
}

GuestVirtualAddress CryptUnprotectData::pOptionalEntropy() const { return pOptionalEntropy_; }
void CryptUnprotectData::pOptionalEntropy(const GuestVirtualAddress& value) {
    set_address_argument(2, value);
    pOptionalEntropy_ = value;
}

GuestVirtualAddress CryptUnprotectData::pvReserved() const { return pvReserved_; }
void CryptUnprotectData::pvReserved(const GuestVirtualAddress& value) {
    set_address_argument(3, pvReserved_);
    pvReserved_ = value;
}

GuestVirtualAddress CryptUnprotectData::pPromptStruct() const { return pPromptStruct_; }
void CryptUnprotectData::pPromptStruct(const GuestVirtualAddress& value) {
    set_address_argument(4, value);
    pPromptStruct_ = value;
}

uint32_t CryptUnprotectData::dwFlags() const { return dwFlags_; }
void CryptUnprotectData::dwFlags(uint32_t value) {
    set_argument(5, value);
    dwFlags_ = value;
}

GuestVirtualAddress CryptUnprotectData::pDataOut() const { return pDataOut_; }
void CryptUnprotectData::pDataOut(const GuestVirtualAddress& value) {
    set_address_argument(6, value);
    pDataOut_ = value;
}

/* Helpers */
const CRYPTOAPI_BLOB* CryptUnprotectData::DataIn() const {
    if (!DataIn_ && pDataIn_)
        DataIn_ = CRYPTOAPI_BLOB::make_unique(pDataIn_, x64());
    return DataIn_.get();
}

CRYPTOAPI_BLOB* CryptUnprotectData::DataIn() {
    const auto* const_this = this;
    return const_cast<CRYPTOAPI_BLOB*>(const_this->DataIn());
}

GuestVirtualAddress CryptUnprotectData::pszDataDescr() const {
    if (ppszDataDescr_) {
        return get_ptr(ppszDataDescr_);
    }
    return NullGuestAddress();
}

void CryptUnprotectData::pszDataDescr(const GuestVirtualAddress& value) {
    if (ppszDataDescr_) {
        set_ptr(ppszDataDescr_, value);
    }
}

const CRYPTOAPI_BLOB* CryptUnprotectData::OptionalEntropy() const {
    if (!OptionalEntropy_ && pOptionalEntropy_)
        OptionalEntropy_ = CRYPTOAPI_BLOB::make_unique(pOptionalEntropy_, x64());
    return OptionalEntropy_.get();
}

CRYPTOAPI_BLOB* CryptUnprotectData::OptionalEntropy() {
    const auto* const_this = this;
    return const_cast<CRYPTOAPI_BLOB*>(const_this->OptionalEntropy());
}

std::string CryptUnprotectData::DataDescr() const {
    const auto pDataDescr = pszDataDescr();
    if (pDataDescr) {
        auto result = map_guest_cstr(pDataDescr);
        return std::string(result.get(), result.length());
    }
    return std::string();
}

const CRYPTPROTECT_PROMPTSTRUCT* CryptUnprotectData::PromptStruct() const {
    if (!PromptStruct_ && pPromptStruct_) {
        PromptStruct_ = CRYPTPROTECT_PROMPTSTRUCT::make_unique(pPromptStruct_, x64());
    }
    return PromptStruct_.get();
}

CRYPTPROTECT_PROMPTSTRUCT* CryptUnprotectData::PromptStruct() {
    const auto* const_this = this;
    return const_cast<CRYPTPROTECT_PROMPTSTRUCT*>(const_this->PromptStruct());
}

const CRYPTOAPI_BLOB* CryptUnprotectData::DataOut() const {
    if (!DataOut_ && pDataOut_)
        DataOut_ = CRYPTOAPI_BLOB::make_unique(pDataOut_, x64());
    return DataOut_.get();
}

CRYPTOAPI_BLOB* CryptUnprotectData::DataOut() {
    const auto* const_this = this;
    return const_cast<CRYPTOAPI_BLOB*>(const_this->DataOut());
}

bool CryptUnprotectData::result() const { return raw_return_value(); }

const std::string& CryptUnprotectData::function_name() const { return FunctionName; }
const std::string& CryptUnprotectData::library_name() const { return LibraryName; }
void CryptUnprotectData::write(std::ostream& os) const {
    boost::io::ios_flags_saver ifs(os);
    // TODO
}

CryptUnprotectData::CryptUnprotectData(Event& event) : WindowsFunctionCall(event, ArgumentCount) {
    pDataIn_ = get_address_argument(0);
    ppszDataDescr_ = get_address_argument(1);
    pOptionalEntropy_ = get_address_argument(2);
    pvReserved_ = get_address_argument(3);
    pPromptStruct_ = get_address_argument(4);
    dwFlags_ = get_argument(5);
    pDataOut_ = get_address_argument(6);
}

CryptUnprotectData::~CryptUnprotectData() = default;

} // namespace crypt32
} // namespace windows
} // namespace introvirt