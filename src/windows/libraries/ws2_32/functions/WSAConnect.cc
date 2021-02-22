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
#include <introvirt/windows/libraries/ws2_32/functions/WSAConnect.hh>

#include <boost/io/ios_state.hpp>

#include "../../helpers.hh"

namespace introvirt {
namespace windows {
namespace ws2_32 {

/* Input arguments */
DEFINE_VALUE_GETTER_SETTER(WSAConnect, s, 0, SOCKET);
DEFINE_ADDRESS_GETTER_SETTER(WSAConnect, pName, 1);
DEFINE_VALUE_GETTER_SETTER(WSAConnect, namelen, 2, int32_t);
DEFINE_ADDRESS_GETTER_SETTER(WSAConnect, lpCallerData, 3);
DEFINE_ADDRESS_GETTER_SETTER(WSAConnect, lpCalleeData, 4);
DEFINE_ADDRESS_GETTER_SETTER(WSAConnect, lpSQOS, 5);
DEFINE_ADDRESS_GETTER_SETTER(WSAConnect, lpGQOS, 6);

/* Helpers */
const SOCKADDR* WSAConnect::name() const {
    if (!name_ && pName_) {
        name_ = SOCKADDR::make_unique(pName(), x64());
    }
    return name_.get();
}
SOCKADDR* WSAConnect::name() {
    const auto* const_this = this;
    return const_cast<SOCKADDR*>(const_this->name());
}

int32_t WSAConnect::result() const { return raw_return_value(); }

const std::string& WSAConnect::function_name() const { return FunctionName; }
const std::string& WSAConnect::library_name() const { return LibraryName; }
void WSAConnect::write(std::ostream& os) const {
    boost::io::ios_flags_saver ifs(os);
    // TODO
}

WSAConnect::WSAConnect(Event& event) : WindowsFunctionCall(event, ArgumentCount) {
    s_ = get_argument(0);
    pName_ = get_address_argument(1);
    namelen_ = get_argument(2);
    lpCallerData_ = get_address_argument(3);
    lpCalleeData_ = get_address_argument(4);
    lpSQOS_ = get_address_argument(5);
    lpGQOS_ = get_address_argument(6);
}

WSAConnect::~WSAConnect() = default;

} // namespace ws2_32
} // namespace windows
} // namespace introvirt