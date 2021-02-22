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
#include <introvirt/windows/libraries/ws2_32/functions/WSASendTo.hh>

#include <boost/io/ios_state.hpp>

#include "../../helpers.hh"

namespace introvirt {
namespace windows {
namespace ws2_32 {

/* Input arguments */
DEFINE_VALUE_GETTER_SETTER(WSASendTo, s, 0, SOCKET);
DEFINE_ADDRESS_GETTER_SETTER(WSASendTo, lpBuffers, 1);
DEFINE_VALUE_GETTER_SETTER(WSASendTo, dwBufferCount, 2, uint32_t);
DEFINE_ADDRESS_GETTER_SETTER(WSASendTo, lpNumberOfBytesSent, 3);
DEFINE_VALUE_GETTER_SETTER(WSASendTo, dwFlags, 4, uint32_t);
DEFINE_ADDRESS_GETTER_SETTER(WSASendTo, lpTo, 5);
DEFINE_VALUE_GETTER_SETTER(WSASendTo, iTolen, 6, int32_t);
DEFINE_ADDRESS_GETTER_SETTER(WSASendTo, lpOverlapped, 7);
DEFINE_ADDRESS_GETTER_SETTER(WSASendTo, lpCompletionRoutine, 8);

/* Helpers */
uint32_t WSASendTo::NumberOfBytesSent() const {
    if (lpNumberOfBytesSent_) {
        return *guest_ptr<uint32_t>(lpNumberOfBytesSent_);
    }
    // TODO: Throw an exception
    return 0;
}
void WSASendTo::NumberOfBytesSent(uint32_t NumberOfBytesSent) {
    if (lpNumberOfBytesSent_) {
        *guest_ptr<uint32_t>(lpNumberOfBytesSent_) = NumberOfBytesSent;
        return;
    }
    // TODO: Throw an exception
}

const SOCKADDR* WSASendTo::To() const {
    if (!to_ && lpTo_) {
        to_ = SOCKADDR::make_unique(lpTo(), x64());
    }
    return to_.get();
}
SOCKADDR* WSASendTo::To() {
    const auto* const_this = this;
    return const_cast<SOCKADDR*>(const_this->To());
}

int32_t WSASendTo::result() const { return raw_return_value(); }

const std::string& WSASendTo::function_name() const { return FunctionName; }
const std::string& WSASendTo::library_name() const { return LibraryName; }
void WSASendTo::write(std::ostream& os) const {
    boost::io::ios_flags_saver ifs(os);
    // TODO
}

WSASendTo::WSASendTo(Event& event) : WindowsFunctionCall(event, ArgumentCount) {
    s_ = get_argument(0);
    lpBuffers_ = get_address_argument(1);
    dwBufferCount_ = get_argument(2);
    lpNumberOfBytesSent_ = get_address_argument(3);
    dwFlags_ = get_argument(4);
    lpTo_ = get_address_argument(5);
    iTolen_ = get_argument(6);
    lpOverlapped_ = get_address_argument(7);
    lpCompletionRoutine_ = get_address_argument(8);
}

WSASendTo::~WSASendTo() = default;

} // namespace ws2_32
} // namespace windows
} // namespace introvirt