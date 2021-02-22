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
#include <introvirt/windows/libraries/ws2_32/functions/WSASend.hh>

#include <boost/io/ios_state.hpp>

#include "../../helpers.hh"

namespace introvirt {
namespace windows {
namespace ws2_32 {

/* Input arguments */
DEFINE_VALUE_GETTER_SETTER(WSASend, s, 0, SOCKET);
DEFINE_ADDRESS_GETTER_SETTER(WSASend, lpBuffers, 1);
DEFINE_VALUE_GETTER_SETTER(WSASend, dwBufferCount, 2, uint32_t);
DEFINE_ADDRESS_GETTER_SETTER(WSASend, lpNumberOfBytesSent, 3);
DEFINE_VALUE_GETTER_SETTER(WSASend, dwFlags, 4, uint32_t);
DEFINE_ADDRESS_GETTER_SETTER(WSASend, lpOverlapped, 5);
DEFINE_ADDRESS_GETTER_SETTER(WSASend, lpCompletionRoutine, 6);

/* Helpers */
uint32_t WSASend::NumberOfBytesSent() const {
    if (lpNumberOfBytesSent_) {
        return *guest_ptr<uint32_t>(lpNumberOfBytesSent_);
    }
    // TODO: Throw an exception
    return 0;
}
void WSASend::NumberOfBytesSent(uint32_t NumberOfBytesSent) {
    if (lpNumberOfBytesSent_) {
        *guest_ptr<uint32_t>(lpNumberOfBytesSent_) = NumberOfBytesSent;
        return;
    }
    // TODO: Throw an exception
}

int32_t WSASend::result() const { return raw_return_value(); }

const std::string& WSASend::function_name() const { return FunctionName; }
const std::string& WSASend::library_name() const { return LibraryName; }
void WSASend::write(std::ostream& os) const {
    boost::io::ios_flags_saver ifs(os);
    // TODO
}

WSASend::WSASend(Event& event) : WindowsFunctionCall(event, ArgumentCount) {
    s_ = get_argument(0);
    lpBuffers_ = get_address_argument(1);
    dwBufferCount_ = get_argument(2);
    lpNumberOfBytesSent_ = get_address_argument(3);
    dwFlags_ = get_argument(4);
    lpOverlapped_ = get_address_argument(5);
    lpCompletionRoutine_ = get_address_argument(6);
}

WSASend::~WSASend() = default;

} // namespace ws2_32
} // namespace windows
} // namespace introvirt