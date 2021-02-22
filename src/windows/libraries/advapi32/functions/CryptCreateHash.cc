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
#include <introvirt/windows/libraries/advapi32/functions/CryptCreateHash.hh>

#include <boost/io/ios_state.hpp>

namespace introvirt {
namespace windows {
namespace advapi32 {

HCRYPTPROV CryptCreateHash::hProv() const { return hProv_; }
void CryptCreateHash::hProv(HCRYPTPROV value) {
    set_argument(0, value);
    hProv_ = value;
}

ALG_ID CryptCreateHash::Algid() const { return Algid_; }
void CryptCreateHash::Algid(ALG_ID value) {
    set_argument(1, value);
    Algid_ = value;
}

HCRYPTKEY CryptCreateHash::hKey() const { return Algid_; }
void CryptCreateHash::hKey(HCRYPTKEY value) {
    set_argument(2, value);
    Algid_ = static_cast<ALG_ID>(value);
}

uint32_t CryptCreateHash::dwFlags() const { return dwFlags_; }
void CryptCreateHash::dwFlags(uint32_t value) {
    set_argument(3, value);
    dwFlags_ = value;
}

GuestVirtualAddress CryptCreateHash::phHash() const { return phHash_; }
void CryptCreateHash::phHash(const GuestVirtualAddress& value) {
    set_address_argument(4, value);
    phHash_ = value;
}

HCRYPTHASH CryptCreateHash::hHash() const { return get_ptrsize_value(phHash_); }
void CryptCreateHash::hHash(HCRYPTHASH value) { set_ptrsize_value(phHash_, value); }

bool CryptCreateHash::result() const { return raw_return_value(); }
void CryptCreateHash::result(bool value) { raw_return_value(value); }

CryptCreateHash::CryptCreateHash(Event& event) : WindowsFunctionCall(event, ArgumentCount) {
    hProv_ = get_argument(0);
    Algid_ = static_cast<ALG_ID>(get_argument(1));
    hKey_ = get_argument(2);
    dwFlags_ = get_argument(3);
    phHash_ = get_address_argument(4);
}

CryptCreateHash::~CryptCreateHash() = default;

void CryptCreateHash::write(std::ostream& os) const {
    boost::io::ios_flags_saver ifs(os);
    os << std::hex;
    os << '\t' << "hProv: 0x" << hProv() << '\n';
    os << '\t' << "Algid: [0x" << static_cast<uint32_t>(Algid()) << "] " << Algid() << '\n';
    os << '\t' << "hKey: 0x" << hKey() << '\n';
    os << '\t' << "dwFlags: 0x" << dwFlags() << '\n';
    os << '\t' << "phHash: " << phHash() << '\n';
    if (returned())
        os << '\t' << "Result: " << result() << '\n';
}

const std::string& CryptCreateHash::function_name() const { return FunctionName; }
const std::string& CryptCreateHash::library_name() const { return LibraryName; }

} // namespace advapi32
} // namespace windows
} // namespace introvirt
