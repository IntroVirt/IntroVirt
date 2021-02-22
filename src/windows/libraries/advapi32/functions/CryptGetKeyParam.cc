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
#include <introvirt/core/event/ThreadLocalEvent.hh>
#include <introvirt/windows/libraries/advapi32/functions/CryptGetKeyParam.hh>

#include "windows/injection/function.hh"

#include <boost/io/ios_state.hpp>

namespace introvirt {
namespace windows {
namespace advapi32 {

HCRYPTKEY CryptGetKeyParam::hKey() const { return hKey_; }
void CryptGetKeyParam::hKey(HCRYPTKEY value) {
    set_argument(0, value);
    hKey_ = value;
}

KP_VALUE CryptGetKeyParam::dwParam() const { return dwParam_; }
void CryptGetKeyParam::dwParam(KP_VALUE value) {
    set_argument(1, static_cast<uint32_t>(value));
    dwParam_ = value;
}

GuestVirtualAddress CryptGetKeyParam::pbData() const { return pbData_; }
void CryptGetKeyParam::pbData(const GuestVirtualAddress& value) {
    set_address_argument(2, value);
    pbData_ = value;
}

GuestVirtualAddress CryptGetKeyParam::pdwDataLen() const { return pdwDataLen_; }
void CryptGetKeyParam::pdwDataLen(const GuestVirtualAddress& value) {
    set_address_argument(3, value);
    pdwDataLen_ = value;
}

uint32_t CryptGetKeyParam::dwFlags() const { return dwFlags_; }
void CryptGetKeyParam::dwFlags(uint32_t value) {
    set_argument(4, value);
    dwFlags_ = value;
}

bool CryptGetKeyParam::result() const { return raw_return_value(); }
void CryptGetKeyParam::result(bool value) { raw_return_value(value); }

bool CryptGetKeyParam::inject(HCRYPTKEY hKey, KP_VALUE dwParam, const GuestVirtualAddress& pbData,
                              const GuestVirtualAddress& pdwDataLen, uint32_t dwFlags) {

    Event& event = ThreadLocalEvent::get();

    inject::FunctionInjector<CryptGetKeyParam> injector(event);

    CryptGetKeyParam handler(event, hKey, dwParam, pbData, pdwDataLen, dwFlags);
    injector.call(handler);
    return handler.result();
}

CryptGetKeyParam::CryptGetKeyParam(Event& event, HCRYPTKEY hKey, KP_VALUE dwParam,
                                   const GuestVirtualAddress& pbData,
                                   const GuestVirtualAddress& pdwDataLen, uint32_t dwFlags)
    : WindowsFunctionCall(event, ArgumentCount) {

    this->hKey(hKey);
    this->dwParam(dwParam);
    this->pbData(pbData);
    this->pdwDataLen(pdwDataLen);
    this->dwFlags(dwFlags);
}

CryptGetKeyParam::CryptGetKeyParam(Event& event) : WindowsFunctionCall(event, ArgumentCount) {
    hKey_ = get_argument(0);
    dwParam_ = static_cast<KP_VALUE>(get_argument(1));
    pbData_ = get_address_argument(2);
    pdwDataLen_ = get_address_argument(3);
    dwFlags_ = get_argument(4);
}

CryptGetKeyParam::~CryptGetKeyParam() = default;

void CryptGetKeyParam::write(std::ostream& os) const {
    boost::io::ios_flags_saver ifs(os);
    os << std::hex;
    os << '\t' << "hKey: 0x" << hKey() << '\n';
    os << '\t' << "dwParam: " << dwParam() << '\n';
    os << '\t' << "pbData: " << pbData() << '\n';
    os << '\t' << "pdwDataLen: " << pdwDataLen() << '\n';
    os << '\t' << "dwFlags: 0x" << dwFlags() << '\n';

    if (returned())
        os << '\t' << "Result: " << result() << '\n';
}

const std::string& CryptGetKeyParam::function_name() const { return FunctionName; }
const std::string& CryptGetKeyParam::library_name() const { return LibraryName; }

} // namespace advapi32
} // namespace windows
} // namespace introvirt
