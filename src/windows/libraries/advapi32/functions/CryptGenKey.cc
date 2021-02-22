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
#include <introvirt/windows/libraries/advapi32/functions/CryptGenKey.hh>

#include <boost/io/ios_state.hpp>

namespace introvirt {
namespace windows {
namespace advapi32 {

HCRYPTPROV CryptGenKey::hProv() const { return hProv_; }
void CryptGenKey::hProv(HCRYPTPROV value) {
    set_argument(0, value);
    hProv_ = value;
}

ALG_ID CryptGenKey::Algid() const { return Algid_; }
void CryptGenKey::Algid(ALG_ID value) {
    set_argument(1, value);
    Algid_ = value;
}

uint32_t CryptGenKey::dwFlags() const { return dwFlags_; }
void CryptGenKey::dwFlags(uint32_t value) {
    set_argument(2, value);
    dwFlags_ = value;
}

GuestVirtualAddress CryptGenKey::phKey() const { return phKey_; }
void CryptGenKey::phKey(const GuestVirtualAddress& value) {
    set_address_argument(3, value);
    phKey_ = value;
}

HCRYPTKEY CryptGenKey::hKey() const { return get_ptrsize_value(phKey_); }
void CryptGenKey::hKey(HCRYPTKEY value) { set_ptrsize_value(phKey_, value); }

bool CryptGenKey::result() const { return raw_return_value(); }
void CryptGenKey::result(bool value) { raw_return_value(value); }

CryptGenKey::CryptGenKey(Event& event) : WindowsFunctionCall(event, ArgumentCount) {
    hProv_ = get_argument(0);
    Algid_ = static_cast<ALG_ID>(get_argument(1));
    dwFlags_ = get_argument(2);
    phKey_ = get_address_argument(3);
}

CryptGenKey::~CryptGenKey() = default;

void CryptGenKey::write(std::ostream& os) const {
    boost::io::ios_flags_saver ifs(os);
    os << std::hex;
    os << '\t' << "hProv: 0x" << hProv() << '\n';
    os << '\t' << "Algid: [0x" << static_cast<uint32_t>(Algid()) << "] " << Algid() << '\n';
    os << '\t' << "dwFlags: 0x" << dwFlags() << '\n';
    os << '\t' << "phKey: " << phKey() << '\n';
    if (returned())
        os << '\t' << "Result: " << result() << '\n';
}

const std::string& CryptGenKey::function_name() const { return FunctionName; }
const std::string& CryptGenKey::library_name() const { return LibraryName; }

} // namespace advapi32
} // namespace windows
} // namespace introvirt
