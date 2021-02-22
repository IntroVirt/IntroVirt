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
#include <introvirt/windows/common/Utf16String.hh>
#include <introvirt/windows/libraries/advapi32/functions/CryptAcquireContextW.hh>

#include <boost/io/ios_state.hpp>

namespace introvirt {
namespace windows {
namespace advapi32 {

GuestVirtualAddress CryptAcquireContextW::phProv() const { return phProv_; }
void CryptAcquireContextW::phProv(const GuestVirtualAddress& value) {
    set_address_argument(0, value);
    phProv_ = value;
}

GuestVirtualAddress CryptAcquireContextW::pszContainer() const { return pszContainer_; }
void CryptAcquireContextW::pszContainer(const GuestVirtualAddress& value) {
    set_address_argument(1, value);
    pszContainer_ = value;
}

GuestVirtualAddress CryptAcquireContextW::pszProvider() const { return pszProvider_; }
void CryptAcquireContextW::pszProvider(const GuestVirtualAddress& value) {
    set_address_argument(2, value);
    pszProvider_ = value;
}

uint32_t CryptAcquireContextW::dwProvType() const { return dwProvType_; }
void CryptAcquireContextW::dwProvType(uint32_t value) {
    set_argument(3, static_cast<uint32_t>(value));
    dwProvType_ = value;
}

uint32_t CryptAcquireContextW::dwFlags() const { return dwFlags_; }
void CryptAcquireContextW::dwFlags(uint32_t value) {
    set_argument(4, value);
    dwFlags_ = value;
}

HCRYPTPROV CryptAcquireContextW::hProv() const { return get_ptrsize_value(phProv_); }
void CryptAcquireContextW::hProv(HCRYPTPROV value) { set_ptrsize_value(phProv_, value); }

std::string CryptAcquireContextW::szContainer() const {
    if (pszContainer_) {
        auto guest_str(map_guest_wstr(pszContainer_));
        std::u16string_view u16str(guest_str);
        return Utf16String::convert(u16str);
    }
    return std::string();
}

std::string CryptAcquireContextW::szProvider() const {
    if (pszProvider_) {
        auto guest_str(map_guest_wstr(pszProvider_));
        std::u16string_view u16str(guest_str);
        return Utf16String::convert(u16str);
    }
    return std::string();
}

bool CryptAcquireContextW::result() const { return raw_return_value(); }
void CryptAcquireContextW::result(bool value) { raw_return_value(value); }

CryptAcquireContextW::CryptAcquireContextW(Event& event)
    : WindowsFunctionCall(event, ArgumentCount) {
    phProv_ = get_address_argument(0);
    pszContainer_ = get_address_argument(1);
    pszProvider_ = get_address_argument(2);
    dwProvType_ = static_cast<uint32_t>(get_argument(3));
    dwFlags_ = get_argument(4);
}

CryptAcquireContextW::~CryptAcquireContextW() = default;

void CryptAcquireContextW::write(std::ostream& os) const {
    boost::io::ios_flags_saver ifs(os);
    os << std::hex;
    os << '\t' << "phProv: [" << phProv() << "] ";
    if (phProv()) {
        os << " 0x" << hProv();
    }
    os << '\n';

    os << '\t' << "szContainer: " << szContainer() << '\n';
    os << '\t' << "szProvider: " << szProvider() << '\n';
    os << '\t' << "dwProvType: " << dwProvType() << '\n';
    os << '\t' << "dwFlags: 0x" << dwFlags() << '\n';
    if (returned())
        os << '\t' << "Result: " << result() << '\n';
}

const std::string& CryptAcquireContextW::function_name() const { return FunctionName; }
const std::string& CryptAcquireContextW::library_name() const { return LibraryName; }

} // namespace advapi32
} // namespace windows
} // namespace introvirt
