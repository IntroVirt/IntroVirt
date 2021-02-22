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
#include <introvirt/windows/libraries/ws2_32/functions/socket.hh>

#include <boost/io/ios_state.hpp>

namespace introvirt {
namespace windows {
namespace ws2_32 {

/* Input arguments */
int32_t socket::af() const { return af_; }
void socket::af(int32_t af) {
    set_argument(0, af);
    af_ = af;
}

int32_t socket::type() const { return type_; }
void socket::type(int32_t type) {
    set_argument(1, type);
    type_ = type;
}

int32_t socket::protocol() const { return protocol_; }
void socket::protocol(int32_t protocol) {
    set_argument(2, protocol);
    protocol_ = protocol;
}

SOCKET socket::result() const {
    static constexpr SOCKET INVALID_SOCKET_32 = 0xFFFFFFFF;
    SOCKET result = raw_return_value();
    // Handle 32-bit error code
    if (!x64() && result == INVALID_SOCKET_32) {
        result = INVALID_SOCKET;
    }
    return result;
}

const std::string& socket::function_name() const { return FunctionName; }
const std::string& socket::library_name() const { return LibraryName; }
void socket::write(std::ostream& os) const {
    boost::io::ios_flags_saver ifs(os);
    // TODO
}

socket::socket(Event& event) : WindowsFunctionCall(event, ArgumentCount) {
    af_ = get_argument(0);
    type_ = get_argument(1);
    protocol_ = get_argument(2);
}

socket::~socket() = default;

} // namespace ws2_32
} // namespace windows
} // namespace introvirt