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
#include <introvirt/windows/libraries/advapi32/functions/CryptEncrypt.hh>

#include <boost/io/ios_state.hpp>

namespace introvirt {
namespace windows {
namespace advapi32 {

HCRYPTKEY CryptEncrypt::hKey() const { return hKey_; }
void CryptEncrypt::hKey(HCRYPTKEY value) {
    set_argument(0, value);
    hKey_ = value;
}

HCRYPTHASH CryptEncrypt::hHash() const { return hHash_; }
void CryptEncrypt::hHash(HCRYPTHASH value) {
    set_argument(1, value);
    hHash_ = value;
}

bool CryptEncrypt::Final() const { return Final_; }
void CryptEncrypt::Final(bool value) {
    set_argument(2, static_cast<uint64_t>(value));
    Final_ = value;
}

uint32_t CryptEncrypt::dwFlags() const { return dwFlags_; }
void CryptEncrypt::dwFlags(uint32_t value) {
    set_argument(3, value);
    dwFlags_ = value;
}

GuestVirtualAddress CryptEncrypt::pbData() const { return pbData_; }
void CryptEncrypt::pbData(const GuestVirtualAddress& value) {
    set_address_argument(4, value);
    pbData_ = value;
}

GuestVirtualAddress CryptEncrypt::pdwDataLen() const { return pdwDataLen_; }
void CryptEncrypt::pdwDataLen(const GuestVirtualAddress& value) {
    set_address_argument(5, value);
    pdwDataLen_ = value;
}

uint32_t CryptEncrypt::dwBufLen() const { return dwBufLen_; }
void CryptEncrypt::dwBufLen(uint32_t value) {
    set_argument(6, value);
    dwBufLen_ = value;
}

bool CryptEncrypt::result() const { return raw_return_value(); }
void CryptEncrypt::result(bool value) { raw_return_value(value); }

CryptEncrypt::CryptEncrypt(Event& event) : WindowsFunctionCall(event, ArgumentCount) {
    hKey_ = get_argument(0);
    hHash_ = get_argument(1);
    Final_ = static_cast<bool>(get_argument(2));
    dwFlags_ = get_argument(3);
    pbData_ = get_address_argument(4);
    pdwDataLen_ = get_address_argument(5);
    dwBufLen_ = get_argument(6);
}

CryptEncrypt::~CryptEncrypt() = default;

void CryptEncrypt::write(std::ostream& os) const {
    boost::io::ios_flags_saver ifs(os);
    os << std::hex;
    os << '\t' << "hKey: 0x" << hKey() << '\n';
    os << '\t' << "hExpKey: 0x" << hHash() << '\n';
    os << '\t' << "Final: " << Final() << '\n';
    os << '\t' << "dwFlags: 0x" << dwFlags() << '\n';
    os << '\t' << "pbData: " << pbData() << '\n';
    os << '\t' << "pdwDataLen: " << pdwDataLen() << '\n';
    os << '\t' << "dwBufLen: " << dwBufLen() << '\n';
    if (returned())
        os << '\t' << "Result: " << result() << '\n';
}

const std::string& CryptEncrypt::function_name() const { return FunctionName; }
const std::string& CryptEncrypt::library_name() const { return LibraryName; }

} // namespace advapi32
} // namespace windows
} // namespace introvirt
