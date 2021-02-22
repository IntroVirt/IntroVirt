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
#include <introvirt/windows/libraries/crypt32/functions/CryptProtectData.hh>

#include <boost/io/ios_state.hpp>

namespace introvirt {
namespace windows {
namespace crypt32 {

/* Input arguments */
GuestVirtualAddress CryptProtectData::pDataIn() const { return pDataIn_; }
void CryptProtectData::pDataIn(const GuestVirtualAddress& value) {
    set_address_argument(0, value);
    pDataIn_ = value;
}

GuestVirtualAddress CryptProtectData::pszDataDescr() const { return pszDataDescr_; }
void CryptProtectData::pszDataDescr(const GuestVirtualAddress& value) {
    set_address_argument(1, value);
    pszDataDescr_ = value;
}

GuestVirtualAddress CryptProtectData::pOptionalEntropy() const { return pOptionalEntropy_; }
void CryptProtectData::pOptionalEntropy(const GuestVirtualAddress& value) {
    set_address_argument(2, value);
    pOptionalEntropy_ = value;
}

GuestVirtualAddress CryptProtectData::pvReserved() const { return pvReserved_; }
void CryptProtectData::pvReserved(const GuestVirtualAddress& value) {
    set_address_argument(3, pvReserved_);
    pvReserved_ = value;
}

GuestVirtualAddress CryptProtectData::pPromptStruct() const { return pPromptStruct_; }
void CryptProtectData::pPromptStruct(const GuestVirtualAddress& value) {
    set_address_argument(4, value);
    pPromptStruct_ = value;
}

uint32_t CryptProtectData::dwFlags() const { return dwFlags_; }
void CryptProtectData::dwFlags(uint32_t value) {
    set_argument(5, value);
    dwFlags_ = value;
}

GuestVirtualAddress CryptProtectData::pDataOut() const { return pDataOut_; }
void CryptProtectData::pDataOut(const GuestVirtualAddress& value) {
    set_address_argument(6, value);
    pDataOut_ = value;
}

/* Helpers */
const CRYPTOAPI_BLOB* CryptProtectData::DataIn() const {
    if (!DataIn_ && pDataIn_)
        DataIn_ = CRYPTOAPI_BLOB::make_unique(pDataIn_, x64());
    return DataIn_.get();
}

CRYPTOAPI_BLOB* CryptProtectData::DataIn() {
    const auto* const_this = this;
    return const_cast<CRYPTOAPI_BLOB*>(const_this->DataIn());
}

const CRYPTOAPI_BLOB* CryptProtectData::OptionalEntropy() const {
    if (!OptionalEntropy_ && pOptionalEntropy_)
        OptionalEntropy_ = CRYPTOAPI_BLOB::make_unique(pOptionalEntropy_, x64());
    return OptionalEntropy_.get();
}

CRYPTOAPI_BLOB* CryptProtectData::OptionalEntropy() {
    const auto* const_this = this;
    return const_cast<CRYPTOAPI_BLOB*>(const_this->OptionalEntropy());
}

std::string CryptProtectData::DataDescr() const {
    if (pszDataDescr_) {
        auto result = map_guest_cstr(pszDataDescr());
        return std::string(result.get(), result.length());
    }
    return std::string();
}

const CRYPTPROTECT_PROMPTSTRUCT* CryptProtectData::PromptStruct() const {
    if (!PromptStruct_ && pPromptStruct_) {
        PromptStruct_ = CRYPTPROTECT_PROMPTSTRUCT::make_unique(pPromptStruct_, x64());
    }
    return PromptStruct_.get();
}

CRYPTPROTECT_PROMPTSTRUCT* CryptProtectData::PromptStruct() {
    const auto* const_this = this;
    return const_cast<CRYPTPROTECT_PROMPTSTRUCT*>(const_this->PromptStruct());
}

const CRYPTOAPI_BLOB* CryptProtectData::DataOut() const {
    if (!DataOut_ && pDataOut_)
        DataOut_ = CRYPTOAPI_BLOB::make_unique(pDataOut_, x64());
    return DataOut_.get();
}

CRYPTOAPI_BLOB* CryptProtectData::DataOut() {
    const auto* const_this = this;
    return const_cast<CRYPTOAPI_BLOB*>(const_this->DataOut());
}

bool CryptProtectData::result() const { return raw_return_value(); }

const std::string& CryptProtectData::function_name() const { return FunctionName; }
const std::string& CryptProtectData::library_name() const { return LibraryName; }
void CryptProtectData::write(std::ostream& os) const {
    boost::io::ios_flags_saver ifs(os);
    // TODO
}

CryptProtectData::CryptProtectData(Event& event) : WindowsFunctionCall(event, ArgumentCount) {
    pDataIn_ = get_address_argument(0);
    pszDataDescr_ = get_address_argument(1);
    pOptionalEntropy_ = get_address_argument(2);
    pvReserved_ = get_address_argument(3);
    pPromptStruct_ = get_address_argument(4);
    dwFlags_ = get_argument(5);
    pDataOut_ = get_address_argument(6);
}

CryptProtectData::~CryptProtectData() = default;

} // namespace crypt32
} // namespace windows
} // namespace introvirt