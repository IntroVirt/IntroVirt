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
#include <introvirt/windows/libraries/advapi32/functions/CryptHashData.hh>

#include <boost/io/ios_state.hpp>

namespace introvirt {
namespace windows {
namespace advapi32 {

HCRYPTHASH CryptHashData::hHash() const { return hHash_; }
void CryptHashData::hHash(HCRYPTHASH value) {
    set_argument(0, value);
    hHash_ = value;
}

GuestVirtualAddress CryptHashData::pbData() const { return pbData_; }
void CryptHashData::pbData(const GuestVirtualAddress& value) {
    set_address_argument(1, value);
    pbData_ = value;
}

uint32_t CryptHashData::dwDataLen() const { return dwDataLen_; }
void CryptHashData::dwDataLen(uint32_t value) {
    set_argument(2, value);
    dwDataLen_ = value;
}

uint32_t CryptHashData::dwFlags() const { return dwFlags_; }
void CryptHashData::dwFlags(uint32_t value) {
    set_argument(3, value);
    dwFlags_ = value;
}

bool CryptHashData::result() const { return raw_return_value(); }
void CryptHashData::result(bool value) { raw_return_value(value); }

CryptHashData::CryptHashData(Event& event) : WindowsFunctionCall(event, ArgumentCount) {
    hHash_ = get_argument(0);
    pbData_ = get_address_argument(1);
    dwDataLen_ = get_argument(2);
    dwFlags_ = get_argument(3);
}

CryptHashData::~CryptHashData() = default;

void CryptHashData::write(std::ostream& os) const {
    boost::io::ios_flags_saver ifs(os);
    os << std::hex;
    os << '\t' << "hHash: 0x" << hHash() << '\n';
    os << '\t' << "pbData: 0x" << pbData() << '\n';
    os << '\t' << "dwDataLen: 0x" << dwDataLen() << '\n';
    os << '\t' << "dwFlags: 0x" << dwFlags() << '\n';
    if (returned())
        os << '\t' << "Result: " << result() << '\n';
}

const std::string& CryptHashData::function_name() const { return FunctionName; }
const std::string& CryptHashData::library_name() const { return LibraryName; }

} // namespace advapi32
} // namespace windows
} // namespace introvirt
