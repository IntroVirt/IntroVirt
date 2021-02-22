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
#include <introvirt/windows/libraries/ws2_32/functions/ConnectEx.hh>

#include <boost/io/ios_state.hpp>

#include "../../helpers.hh"

namespace introvirt {
namespace windows {
namespace ws2_32 {

/* Input arguments */
DEFINE_VALUE_GETTER_SETTER(ConnectEx, s, 0, SOCKET);
DEFINE_ADDRESS_GETTER_SETTER(ConnectEx, pName, 1);
DEFINE_VALUE_GETTER_SETTER(ConnectEx, namelen, 2, int32_t);
DEFINE_ADDRESS_GETTER_SETTER(ConnectEx, lpSendBuffer, 3);
DEFINE_VALUE_GETTER_SETTER(ConnectEx, dwSendDataLength, 4, uint32_t);
DEFINE_ADDRESS_GETTER_SETTER(ConnectEx, lpdwBytesSent, 5);
DEFINE_ADDRESS_GETTER_SETTER(ConnectEx, lpOverlapped, 6);

/* Helpers */
const SOCKADDR* ConnectEx::name() const {
    if (!name_ && pName_) {
        name_ = SOCKADDR::make_unique(pName(), x64());
    }
    return name_.get();
}
SOCKADDR* ConnectEx::name() {
    const auto* const_this = this;
    return const_cast<SOCKADDR*>(const_this->name());
}

uint32_t ConnectEx::dwBytesSent() const {
    if (lpdwBytesSent_) {
        return *guest_ptr<uint32_t>(lpdwBytesSent_);
    }
    // TODO: Throw an exception ?
    return 0;
}

void ConnectEx::dwBytesSent(uint32_t dwBytesSent) {
    if (lpdwBytesSent_) {
        *guest_ptr<uint32_t>(lpdwBytesSent_) = dwBytesSent;
        return;
    }
    // TODO: Throw an exception ?
}

bool ConnectEx::result() const { return raw_return_value(); }

const std::string& ConnectEx::function_name() const { return FunctionName; }
const std::string& ConnectEx::library_name() const { return LibraryName; }
void ConnectEx::write(std::ostream& os) const {
    boost::io::ios_flags_saver ifs(os);
    // TODO
}

ConnectEx::ConnectEx(Event& event) : WindowsFunctionCall(event, ArgumentCount) {
    s_ = get_argument(0);
    pName_ = get_address_argument(1);
    namelen_ = get_argument(2);
    lpSendBuffer_ = get_address_argument(3);
    dwSendDataLength_ = get_argument(4);
    lpdwBytesSent_ = get_address_argument(5);
    lpOverlapped_ = get_address_argument(6);
}

ConnectEx::~ConnectEx() = default;

} // namespace ws2_32
} // namespace windows
} // namespace introvirt