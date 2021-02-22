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
#include <introvirt/windows/libraries/advapi32/functions/CryptGenRandom.hh>

#include <boost/io/ios_state.hpp>

namespace introvirt {
namespace windows {
namespace advapi32 {

uint64_t CryptGenRandom::hProv() const { return hProv_; }
void CryptGenRandom::hProv(HCRYPTPROV value) {
    set_argument(0, value);
    hProv_ = value;
}

uint32_t CryptGenRandom::dwLen() const { return dwLen_; }
void CryptGenRandom::dwLen(uint32_t value) {
    set_argument(1, value);
    dwLen_ = value;
}

GuestVirtualAddress CryptGenRandom::pbBuffer() const { return pbBuffer_; }
void CryptGenRandom::pbBuffer(const GuestVirtualAddress& value) {
    set_address_argument(2, value);
    pbBuffer_ = value;
}

bool CryptGenRandom::result() const { return raw_return_value(); }
void CryptGenRandom::result(bool value) { raw_return_value(value); }

void CryptGenRandom::write(std::ostream& os) const {
    boost::io::ios_flags_saver ifs(os);
    os << std::hex;
    os << '\t' << "hProv: 0x" << hProv() << '\n';
    os << std::dec;
    os << '\t' << "dwLen: " << dwLen() << '\n';
    os << '\t' << "pbBuffer: " << pbBuffer() << '\n';
    if (returned())
        os << '\t' << "Result: " << result() << '\n';
}

CryptGenRandom::CryptGenRandom(Event& event) : WindowsFunctionCall(event, ArgumentCount) {
    hProv_ = get_argument(0);
    dwLen_ = get_argument(1);
    pbBuffer_ = get_address_argument(2);
}

CryptGenRandom::~CryptGenRandom() = default;

const std::string& CryptGenRandom::function_name() const { return FunctionName; }
const std::string& CryptGenRandom::library_name() const { return LibraryName; }

} // namespace advapi32
} // namespace windows
} // namespace introvirt