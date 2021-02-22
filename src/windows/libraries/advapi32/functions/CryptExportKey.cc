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
#include "windows/injection/function.hh"
#include <introvirt/core/event/ThreadLocalEvent.hh>

#include <introvirt/windows/libraries/advapi32/functions/CryptExportKey.hh>

#include <boost/io/ios_state.hpp>

namespace introvirt {
namespace windows {
namespace advapi32 {

HCRYPTKEY CryptExportKey::hKey() const { return hKey_; }
void CryptExportKey::hKey(HCRYPTKEY value) {
    set_argument(0, value);
    hKey_ = value;
}

HCRYPTKEY CryptExportKey::hExpKey() const { return hExpKey_; }
void CryptExportKey::hExpKey(HCRYPTKEY value) {
    set_argument(1, value);
    hExpKey_ = value;
}

BLOB_TYPE CryptExportKey::dwBlobType() const { return dwBlobType_; }
void CryptExportKey::dwBlobType(BLOB_TYPE value) {
    set_argument(2, static_cast<uint32_t>(value));
    dwBlobType_ = value;
}

uint32_t CryptExportKey::dwFlags() const { return dwFlags_; }
void CryptExportKey::dwFlags(uint32_t value) {
    set_argument(3, value);
    dwFlags_ = value;
}

GuestVirtualAddress CryptExportKey::pbData() const { return pbData_; }
void CryptExportKey::pbData(const GuestVirtualAddress& value) {
    set_address_argument(4, value);
    pbData_ = value;
}

GuestVirtualAddress CryptExportKey::pdwDataLen() const { return pdwDataLen_; }
void CryptExportKey::pdwDataLen(const GuestVirtualAddress& value) {
    set_address_argument(5, value);
    pdwDataLen_ = value;
}

bool CryptExportKey::result() const { return raw_return_value(); }
void CryptExportKey::result(bool value) { raw_return_value(value); }

bool CryptExportKey::inject(HCRYPTKEY hKey, HCRYPTKEY hExpKey, BLOB_TYPE dwBlobType,
                            uint32_t dwFlags, const GuestVirtualAddress& pbData,
                            const GuestVirtualAddress& pdwDataLen) {

    Event& event = ThreadLocalEvent::get();

    inject::FunctionInjector<CryptExportKey> injector(event);

    CryptExportKey handler(event, hKey, hExpKey, dwBlobType, dwFlags, pbData, pdwDataLen);
    injector.call(handler);
    return handler.result();
}

CryptExportKey::CryptExportKey(Event& event, HCRYPTKEY hKey, HCRYPTKEY hExpKey,
                               BLOB_TYPE dwBlobType, uint32_t dwFlags,
                               const GuestVirtualAddress& pbData,
                               const GuestVirtualAddress& pdwDataLen)
    : WindowsFunctionCall(event, ArgumentCount) {

    this->hKey(hKey);
    this->hExpKey(hExpKey);
    this->dwBlobType(dwBlobType);
    this->dwFlags(dwFlags);
    this->pbData(pbData);
    this->pdwDataLen(pdwDataLen);
}

CryptExportKey::CryptExportKey(Event& event) : WindowsFunctionCall(event, ArgumentCount) {
    hKey_ = get_argument(0);
    hExpKey_ = get_argument(1);
    dwBlobType_ = static_cast<BLOB_TYPE>(get_argument(2));
    dwFlags_ = get_argument(3);
    pbData_ = get_address_argument(4);
    pdwDataLen_ = get_address_argument(5);
}

CryptExportKey::~CryptExportKey() = default;

void CryptExportKey::write(std::ostream& os) const {
    boost::io::ios_flags_saver ifs(os);
    os << std::hex;
    os << '\t' << "hKey: 0x" << hKey() << '\n';
    os << '\t' << "hExpKey: 0x" << hExpKey() << '\n';
    os << '\t' << "dwBlobType: " << dwBlobType() << '\n';
    os << '\t' << "dwFlags: 0x" << dwFlags() << '\n';
    os << '\t' << "pbData: " << pbData() << '\n';
    os << '\t' << "pdwDataLen: " << pdwDataLen() << '\n';
    if (returned())
        os << '\t' << "Result: " << result() << '\n';
}

const std::string& CryptExportKey::function_name() const { return FunctionName; }
const std::string& CryptExportKey::library_name() const { return LibraryName; }

} // namespace advapi32
} // namespace windows
} // namespace introvirt