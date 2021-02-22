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
#include <introvirt/windows/libraries/ws2_32/functions/WSAStartup.hh>

#include <boost/io/ios_state.hpp>

namespace introvirt {
namespace windows {
namespace ws2_32 {

/* Input arguments */
uint16_t WSAStartup::wVersionRequired() const { return wVersionRequired_; }
void WSAStartup::wVersionRequired(uint16_t wVersionRequired) {
    set_argument(0, wVersionRequired);
    wVersionRequired_ = wVersionRequired;
}

GuestVirtualAddress WSAStartup::lpWSAData() const { return lpWSAData_; }
void WSAStartup::lpWSAData(const GuestVirtualAddress& gva) {
    set_address_argument(1, gva);
    lpWSAData_ = gva;
    WSAData_.reset();
}

/* Helpers */
const WSADATA* WSAStartup::WSAData() const {
    if (!WSAData_ && lpWSAData_) {
        WSAData_ = WSADATA::make_unique(lpWSAData_, x64());
    }
    return WSAData_.get();
}
WSADATA* WSAStartup::WSAData() {
    const auto* const_this = this;
    return const_cast<WSADATA*>(const_this->WSAData());
}

int32_t WSAStartup::result() const { return raw_return_value(); }

const std::string& WSAStartup::function_name() const { return FunctionName; }
const std::string& WSAStartup::library_name() const { return LibraryName; }
void WSAStartup::write(std::ostream& os) const {
    boost::io::ios_flags_saver ifs(os);
    // TODO
}

WSAStartup::WSAStartup(Event& event) : WindowsFunctionCall(event, ArgumentCount) {
    wVersionRequired_ = get_argument(0);
    lpWSAData_ = get_argument(1);
}

WSAStartup::~WSAStartup() = default;

} // namespace ws2_32
} // namespace windows
} // namespace introvirt