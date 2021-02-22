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
#include <introvirt/windows/libraries/ws2_32/functions/bind.hh>

#include <boost/io/ios_state.hpp>

namespace introvirt {
namespace windows {
namespace ws2_32 {

/* Input arguments */
SOCKET bind::s() const { return s_; }
void bind::s(SOCKET s) {
    set_argument(0, s);
    s_ = s;
}

GuestVirtualAddress bind::pAddr() const { return pAddr_; }
void bind::pAddr(const GuestVirtualAddress& gva) {
    set_address_argument(1, gva);
    pAddr_ = gva;
}

int32_t bind::addrlen() const { return addrlen_; }
void bind::addrlen(int32_t addrlen) {
    set_argument(2, addrlen);
    addrlen_ = addrlen;
}

/* Helpers */
const SOCKADDR* bind::addr() const {
    if (!addr_ && pAddr_) {
        addr_ = SOCKADDR::make_unique(pAddr_, x64());
    }
    return addr_.get();
}
SOCKADDR* bind::addr() {
    const auto* const_this = this;
    return const_cast<SOCKADDR*>(const_this->addr());
}

int32_t bind::result() const { return raw_return_value(); }

const std::string& bind::function_name() const { return FunctionName; }
const std::string& bind::library_name() const { return LibraryName; }
void bind::write(std::ostream& os) const {
    boost::io::ios_flags_saver ifs(os);
    // TODO
}

bind::bind(Event& event) : WindowsFunctionCall(event, ArgumentCount) {
    s_ = get_argument(0);
    pAddr_ = get_address_argument(1);
    addrlen_ = get_argument(2);
}

bind::~bind() = default;

} // namespace ws2_32
} // namespace windows
} // namespace introvirt