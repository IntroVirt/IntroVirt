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
#include <introvirt/windows/libraries/advapi32/functions/CryptAcquireContextA.hh>

#include <boost/io/ios_state.hpp>

namespace introvirt {
namespace windows {
namespace advapi32 {

GuestVirtualAddress CryptAcquireContextA::phProv() const { return phProv_; }
void CryptAcquireContextA::phProv(const GuestVirtualAddress& value) {
    set_address_argument(0, value);
    phProv_ = value;
}

GuestVirtualAddress CryptAcquireContextA::pszContainer() const { return pszContainer_; }
void CryptAcquireContextA::pszContainer(const GuestVirtualAddress& value) {
    set_address_argument(1, value);
    pszContainer_ = value;
}

GuestVirtualAddress CryptAcquireContextA::pszProvider() const { return pszProvider_; }
void CryptAcquireContextA::pszProvider(const GuestVirtualAddress& value) {
    set_address_argument(2, value);
    pszProvider_ = value;
}

uint32_t CryptAcquireContextA::dwProvType() const { return dwProvType_; }
void CryptAcquireContextA::dwProvType(uint32_t value) {
    set_argument(3, static_cast<uint32_t>(value));
    dwProvType_ = value;
}

uint32_t CryptAcquireContextA::dwFlags() const { return dwFlags_; }
void CryptAcquireContextA::dwFlags(uint32_t value) {
    set_argument(4, value);
    dwFlags_ = value;
}

HCRYPTPROV CryptAcquireContextA::hProv() const { return get_ptrsize_value(phProv_); }
void CryptAcquireContextA::hProv(HCRYPTPROV value) { set_ptrsize_value(phProv_, value); }

std::string CryptAcquireContextA::szContainer() const {
    if (pszContainer_) {
        auto mapping = map_guest_cstr(pszContainer_);
        return std::string(mapping.get(), mapping.length());
    }
    return std::string();
}

std::string CryptAcquireContextA::szProvider() const {
    if (pszProvider_) {
        auto mapping = map_guest_cstr(pszProvider_);
        return std::string(mapping.get(), mapping.length());
    }
    return std::string();
}

bool CryptAcquireContextA::result() const { return raw_return_value(); }
void CryptAcquireContextA::result(bool value) { raw_return_value(value); }

CryptAcquireContextA::CryptAcquireContextA(Event& event)
    : WindowsFunctionCall(event, ArgumentCount) {
    phProv_ = get_address_argument(0);
    pszContainer_ = get_address_argument(1);
    pszProvider_ = get_address_argument(2);
    dwProvType_ = static_cast<uint32_t>(get_argument(3));
    dwFlags_ = get_argument(4);
}

CryptAcquireContextA::~CryptAcquireContextA() = default;

void CryptAcquireContextA::write(std::ostream& os) const {
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

const std::string& CryptAcquireContextA::function_name() const { return FunctionName; }
const std::string& CryptAcquireContextA::library_name() const { return LibraryName; }

} // namespace advapi32
} // namespace windows
} // namespace introvirt
