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
#include <introvirt/windows/libraries/ws2_32/functions/recv.hh>

#include <boost/io/ios_state.hpp>

namespace introvirt {
namespace windows {
namespace ws2_32 {

/* Input arguments */
SOCKET recv::s() const { return s_; }
void recv::s(SOCKET s) {
    set_argument(0, s);
    s_ = s;
}

GuestVirtualAddress recv::pBuf() const { return pBuf_; }
void recv::pBuf(const GuestVirtualAddress& gva) {
    set_address_argument(1, gva);
    pBuf_ = gva;
}

int32_t recv::len() const { return len_; }
void recv::len(int32_t len) {
    set_argument(2, len);
    len_ = len;
}

int32_t recv::flags() const { return flags_; }
void recv::flags(int32_t flags) {
    set_argument(3, flags);
    flags_ = flags;
}

/* Helpers */
int32_t recv::result() const { return raw_return_value(); }

const std::string& recv::function_name() const { return FunctionName; }
const std::string& recv::library_name() const { return LibraryName; }
void recv::write(std::ostream& os) const {
    boost::io::ios_flags_saver ifs(os);
    // TODO
}

recv::recv(Event& event) : WindowsFunctionCall(event, ArgumentCount) {
    s_ = get_argument(0);
    pBuf_ = get_address_argument(1);
    len_ = get_argument(2);
    flags_ = get_argument(3);
}

recv::~recv() = default;

} // namespace ws2_32
} // namespace windows
} // namespace introvirt