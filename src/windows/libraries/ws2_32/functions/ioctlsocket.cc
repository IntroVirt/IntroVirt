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
#include <introvirt/windows/libraries/ws2_32/functions/ioctlsocket.hh>

#include <boost/io/ios_state.hpp>

namespace introvirt {
namespace windows {
namespace ws2_32 {

/* Input arguments */
SOCKET ioctlsocket::s() const { return s_; }
void ioctlsocket::s(SOCKET s) {
    set_argument(0, s);
    s_ = s;
}

int32_t ioctlsocket::cmd() const { return s_; }
void ioctlsocket::cmd(int32_t cmd) {
    set_argument(1, cmd);
    cmd_ = cmd;
}

GuestVirtualAddress ioctlsocket::pArg() const { return pArg_; }
void ioctlsocket::pArg(const GuestVirtualAddress& gva) {
    set_address_argument(2, gva);
    pArg_ = gva;
}

/* Helpers */
uint32_t ioctlsocket::arg() const {
    if (pArg_) {
        return *guest_ptr<uint32_t>(pArg_);
    }
    // TODO: Throw an exception?
    return 0;
}

void ioctlsocket::arg(uint32_t arg) {
    if (pArg_) {
        *guest_ptr<uint32_t>(pArg_) = arg;
        return;
    }
    // TODO: Throw an exception?
}

int32_t ioctlsocket::result() const { return raw_return_value(); }

const std::string& ioctlsocket::function_name() const { return FunctionName; }
const std::string& ioctlsocket::library_name() const { return LibraryName; }
void ioctlsocket::write(std::ostream& os) const {
    boost::io::ios_flags_saver ifs(os);
    // TODO
}

ioctlsocket::ioctlsocket(Event& event) : WindowsFunctionCall(event, ArgumentCount) {
    s_ = get_argument(0);
    cmd_ = get_argument(1);
    pArg_ = get_address_argument(2);
}

ioctlsocket::~ioctlsocket() = default;

} // namespace ws2_32
} // namespace windows
} // namespace introvirt