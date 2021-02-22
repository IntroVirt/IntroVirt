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
#include <introvirt/core/exception/InvalidMethodException.hh>
#include <introvirt/windows/libraries/ws2_32/functions/WSAAccept.hh>

#include <boost/io/ios_state.hpp>

namespace introvirt {
namespace windows {
namespace ws2_32 {

/* Input arguments */
SOCKET WSAAccept::s() const { return s_; }
void WSAAccept::s(SOCKET s) {
    set_argument(0, s);
    s_ = s;
}

GuestVirtualAddress WSAAccept::pAddr() const { return pAddr_; }
void WSAAccept::pAddr(const GuestVirtualAddress& gva) {
    set_address_argument(1, gva);
    pAddr_ = gva;
}

GuestVirtualAddress WSAAccept::pAddrLen() const { return pAddrLen_; }
void WSAAccept::pAddrLen(const GuestVirtualAddress& gva) {
    set_address_argument(2, gva);
    pAddrLen_ = gva;
}

GuestVirtualAddress WSAAccept::pfnCondition() const { return pfnCondition_; }
void WSAAccept::pfnCondition(const GuestVirtualAddress& gva) {
    set_address_argument(3, gva);
    pfnCondition_ = gva;
}

GuestVirtualAddress WSAAccept::pDwCallbackData() const { return pDwCallbackData_; }
void WSAAccept::pDwCallbackData(const GuestVirtualAddress& gva) {
    set_address_argument(4, gva);
    pDwCallbackData_ = gva;
}

/* Helpers */
const SOCKADDR* WSAAccept::addr() const {
    if (!addr_ && pAddr_) {
        addr_ = SOCKADDR::make_unique(pAddr(), x64());
    }
    return addr_.get();
}
SOCKADDR* WSAAccept::addr() {
    const auto* const_this = this;
    return const_cast<SOCKADDR*>(const_this->addr());
}

int32_t WSAAccept::addrlen() const {
    if (pAddr_)
        return *guest_ptr<int32_t>(pAddr_);
    // TODO: Throw an exception?
    return 0;
}
void WSAAccept::addrlen(int32_t addrlen) {
    if (pAddr_) {
        *guest_ptr<int32_t>(pAddr_) = addrlen;
        return;
    }
    // TODO: Throw an exception?
}

SOCKET WSAAccept::result() const { return raw_return_value(); }

const std::string& WSAAccept::function_name() const { return FunctionName; }
const std::string& WSAAccept::library_name() const { return LibraryName; }
void WSAAccept::write(std::ostream& os) const {
    boost::io::ios_flags_saver ifs(os);
    // TODO
}

WSAAccept::WSAAccept(Event& event) : WindowsFunctionCall(event, ArgumentCount) {
    s_ = get_argument(0);
    pAddr_ = get_address_argument(1);
    pAddrLen_ = get_address_argument(2);
    pfnCondition_ = get_address_argument(3);
    pDwCallbackData_ = get_address_argument(4);
}

WSAAccept::~WSAAccept() = default;

} // namespace ws2_32
} // namespace windows
} // namespace introvirt