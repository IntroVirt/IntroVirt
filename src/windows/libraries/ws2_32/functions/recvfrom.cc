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
#include <introvirt/windows/libraries/ws2_32/functions/recvfrom.hh>

#include <boost/io/ios_state.hpp>

namespace introvirt {
namespace windows {
namespace ws2_32 {

/* Input arguments */
SOCKET recvfrom::s() const { return s_; }
void recvfrom::s(SOCKET s) {
    set_argument(0, s);
    s_ = s;
}

GuestVirtualAddress recvfrom::pBuf() const { return pBuf_; }
void recvfrom::pBuf(const GuestVirtualAddress& gva) {
    set_address_argument(1, gva);
    pBuf_ = gva;
}

int32_t recvfrom::len() const { return len_; }
void recvfrom::len(int32_t len) {
    set_argument(2, len);
    len_ = len;
}

int32_t recvfrom::flags() const { return flags_; }
void recvfrom::flags(int32_t flags) {
    set_argument(3, flags);
    flags_ = flags;
}

GuestVirtualAddress recvfrom::pFrom() const { return pFrom_; }
void recvfrom::pFrom(const GuestVirtualAddress& gva) {
    set_address_argument(4, gva);
    pFrom_ = gva;
}

int32_t recvfrom::fromlen() const { return fromlen_; }
void recvfrom::fromlen(int32_t fromlen) {
    set_argument(5, fromlen);
    fromlen_ = fromlen;
}

/* Helpers */
const SOCKADDR* recvfrom::from() const {
    if (!from_ && pFrom_) {
        from_ = SOCKADDR::make_unique(pFrom_, x64());
    }
    return from_.get();
}
SOCKADDR* recvfrom::from() {
    const auto* const_this = this;
    return const_cast<SOCKADDR*>(const_this->from());
}

int32_t recvfrom::result() const { return raw_return_value(); }

const std::string& recvfrom::function_name() const { return FunctionName; }
const std::string& recvfrom::library_name() const { return LibraryName; }
void recvfrom::write(std::ostream& os) const {
    boost::io::ios_flags_saver ifs(os);
    // TODO
}

recvfrom::recvfrom(Event& event) : WindowsFunctionCall(event, ArgumentCount) {
    s_ = get_argument(0);
    pBuf_ = get_address_argument(1);
    len_ = get_argument(2);
    flags_ = get_argument(3);
    pFrom_ = get_address_argument(4);
    fromlen_ = get_argument(5);
}

recvfrom::~recvfrom() = default;

} // namespace ws2_32
} // namespace windows
} // namespace introvirt