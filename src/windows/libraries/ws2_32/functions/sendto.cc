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
#include <introvirt/windows/libraries/ws2_32/functions/sendto.hh>

#include <boost/io/ios_state.hpp>

namespace introvirt {
namespace windows {
namespace ws2_32 {

/* Input arguments */
SOCKET sendto::s() const { return s_; }
void sendto::s(SOCKET s) {
    set_argument(0, s);
    s_ = s;
}

GuestVirtualAddress sendto::pBuf() const { return pBuf_; }
void sendto::pBuf(const GuestVirtualAddress& gva) {
    set_address_argument(1, gva);
    pBuf_ = gva;
}

int32_t sendto::len() const { return len_; }
void sendto::len(int32_t len) {
    set_argument(2, len);
    len_ = len;
}

int32_t sendto::flags() const { return flags_; }
void sendto::flags(int32_t flags) {
    set_argument(3, flags);
    flags_ = flags;
}

GuestVirtualAddress sendto::pTo() const { return pTo_; }
void sendto::pTo(const GuestVirtualAddress& gva) {
    set_address_argument(4, gva);
    pTo_ = gva;
}

int32_t sendto::tolen() const { return tolen_; }
void sendto::tolen(int32_t tolen) {
    set_argument(5, tolen);
    tolen_ = tolen;
}

/* Helpers */
const SOCKADDR* sendto::to() const {
    if (!to_ && pTo_) {
        to_ = SOCKADDR::make_unique(pTo_, x64());
    }
    return to_.get();
}
SOCKADDR* sendto::to() {
    const auto* const_this = this;
    return const_cast<SOCKADDR*>(const_this->to());
}

int32_t sendto::result() const { return raw_return_value(); }

const std::string& sendto::function_name() const { return FunctionName; }
const std::string& sendto::library_name() const { return LibraryName; }
void sendto::write(std::ostream& os) const {
    boost::io::ios_flags_saver ifs(os);
    // TODO
}

sendto::sendto(Event& event) : WindowsFunctionCall(event, ArgumentCount) {
    s_ = get_argument(0);
    pBuf_ = get_address_argument(1);
    len_ = get_argument(2);
    flags_ = get_argument(3);
    pTo_ = get_address_argument(4);
    tolen_ = get_argument(5);
}

sendto::~sendto() = default;

} // namespace ws2_32
} // namespace windows
} // namespace introvirt