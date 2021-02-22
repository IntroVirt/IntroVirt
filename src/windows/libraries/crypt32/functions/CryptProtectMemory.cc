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
#include <introvirt/windows/libraries/crypt32/functions/CryptProtectMemory.hh>

#include <boost/io/ios_state.hpp>

namespace introvirt {
namespace windows {
namespace crypt32 {

/* Input arguments */
GuestVirtualAddress CryptProtectMemory::pDataIn() const { return pDataIn_; }
void CryptProtectMemory::pDataIn(const GuestVirtualAddress& value) {
    set_address_argument(0, value);
    pDataIn_ = value;
}

uint32_t CryptProtectMemory::cbDataIn() const { return cbDataIn_; }
void CryptProtectMemory::cbDataIn(uint32_t value) {
    set_argument(1, value);
    cbDataIn_ = value;
}

uint32_t CryptProtectMemory::dwFlags() const { return dwFlags_; }
void CryptProtectMemory::dwFlags(uint32_t value) {
    set_argument(2, value);
    dwFlags_ = value;
}

bool CryptProtectMemory::result() const { return raw_return_value(); }

const std::string& CryptProtectMemory::function_name() const { return FunctionName; }
const std::string& CryptProtectMemory::library_name() const { return LibraryName; }
void CryptProtectMemory::write(std::ostream& os) const {
    boost::io::ios_flags_saver ifs(os);
    // TODO
}

CryptProtectMemory::CryptProtectMemory(Event& event) : WindowsFunctionCall(event, ArgumentCount) {
    pDataIn_ = get_address_argument(0);
    cbDataIn_ = get_argument(1);
    dwFlags_ = get_argument(2);
}

CryptProtectMemory::~CryptProtectMemory() = default;

} // namespace crypt32
} // namespace windows
} // namespace introvirt