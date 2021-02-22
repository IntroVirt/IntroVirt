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
#include <introvirt/windows/libraries/ws2_32/functions/accept.hh>

#include <boost/io/ios_state.hpp>

namespace introvirt {
namespace windows {
namespace ws2_32 {

/* Input arguments */
SOCKET accept::s() const { return s_; }
void accept::s(SOCKET s) {
    set_argument(0, s);
    s_ = s;
}

GuestVirtualAddress accept::pAddr() const { return pAddr_; }
void accept::pAddr(const GuestVirtualAddress& gva) {
    set_address_argument(1, gva);
    pAddr_ = gva;
}

GuestVirtualAddress accept::pAddrLen() const { return pAddrLen_; }
void accept::pAddrLen(const GuestVirtualAddress& gva) {
    set_address_argument(2, gva);
    pAddrLen_ = gva;
}

/* Helpers */
const SOCKADDR* accept::addr() const {
    if (!addr_ && pAddr_) {
        addr_ = SOCKADDR::make_unique(pAddr(), x64());
    }
    return addr_.get();
}
SOCKADDR* accept::addr() {
    const auto* const_this = this;
    return const_cast<SOCKADDR*>(const_this->addr());
}

int32_t accept::addrlen() const {
    if (pAddr_)
        return *guest_ptr<int32_t>(pAddr_);
    // TODO: Throw an exception?
    return 0;
}
void accept::addrlen(int32_t addrlen) {
    if (pAddr_) {
        *guest_ptr<int32_t>(pAddr_) = addrlen;
        return;
    }
    // TODO: Throw an exception?
}

SOCKET accept::result() const { return raw_return_value(); }

const std::string& accept::function_name() const { return FunctionName; }
const std::string& accept::library_name() const { return LibraryName; }
void accept::write(std::ostream& os) const {
    boost::io::ios_flags_saver ifs(os);
    // TODO
}

accept::accept(Event& event) : WindowsFunctionCall(event, ArgumentCount) {
    s_ = get_argument(0);
    pAddr_ = get_address_argument(1);
    pAddrLen_ = get_address_argument(2);
}

accept::~accept() = default;

} // namespace ws2_32
} // namespace windows
} // namespace introvirt