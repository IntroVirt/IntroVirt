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
#include <introvirt/windows/libraries/advapi32/functions/CryptSetKeyParam.hh>

#include <boost/io/ios_state.hpp>

namespace introvirt {
namespace windows {
namespace advapi32 {

HCRYPTKEY CryptSetKeyParam::hKey() const { return hKey_; }
void CryptSetKeyParam::hKey(HCRYPTKEY value) {
    set_argument(0, value);
    hKey_ = value;
}

KP_VALUE CryptSetKeyParam::dwParam() const { return dwParam_; }
void CryptSetKeyParam::dwParam(KP_VALUE value) {
    set_argument(1, static_cast<uint32_t>(value));
    dwParam_ = value;
}

GuestVirtualAddress CryptSetKeyParam::pbData() const { return pbData_; }
void CryptSetKeyParam::pbData(const GuestVirtualAddress& value) {
    set_address_argument(2, value);
    pbData_ = value;
}

uint32_t CryptSetKeyParam::dwFlags() const { return dwFlags_; }
void CryptSetKeyParam::dwFlags(uint32_t value) {
    set_argument(3, value);
    dwFlags_ = value;
}

bool CryptSetKeyParam::result() const { return raw_return_value(); }
void CryptSetKeyParam::result(bool value) { raw_return_value(value); }

CryptSetKeyParam::CryptSetKeyParam(Event& event) : WindowsFunctionCall(event, ArgumentCount) {
    hKey_ = get_argument(0);
    dwParam_ = static_cast<KP_VALUE>(get_argument(1));
    pbData_ = get_address_argument(2);
    dwFlags_ = get_argument(3);
}

CryptSetKeyParam::~CryptSetKeyParam() = default;

void CryptSetKeyParam::write(std::ostream& os) const {
    boost::io::ios_flags_saver ifs(os);
    os << std::hex;
    os << '\t' << "hKey: 0x" << hKey() << '\n';
    os << '\t' << "dwParam: " << dwParam() << '\n';
    os << '\t' << "pbData: " << pbData() << '\n';
    os << '\t' << "dwFlags: 0x" << dwFlags() << '\n';

    if (returned())
        os << '\t' << "Result: " << result() << '\n';
}

const std::string& CryptSetKeyParam::function_name() const { return FunctionName; }
const std::string& CryptSetKeyParam::library_name() const { return LibraryName; }

} // namespace advapi32
} // namespace windows
} // namespace introvirt
