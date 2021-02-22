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
#include <introvirt/windows/libraries/ws2_32/functions/WSASocketA.hh>

#include <boost/io/ios_state.hpp>

#include "../../helpers.hh"

namespace introvirt {
namespace windows {
namespace ws2_32 {

/* Input arguments */
DEFINE_VALUE_GETTER_SETTER(WSASocketA, af, 0, int32_t);
DEFINE_VALUE_GETTER_SETTER(WSASocketA, type, 1, int32_t);
DEFINE_VALUE_GETTER_SETTER(WSASocketA, protocol, 2, int32_t);
DEFINE_ADDRESS_GETTER_SETTER(WSASocketA, lpProtocolInfo, 3);
DEFINE_VALUE_GETTER_SETTER(WSASocketA, g, 4, int32_t);
DEFINE_VALUE_GETTER_SETTER(WSASocketA, dwFlags, 5, int32_t);

SOCKET WSASocketA::result() const {
    static constexpr SOCKET INVALID_SOCKET_32 = 0xFFFFFFFF;
    SOCKET result = raw_return_value();
    // Handle 32-bit error code
    if (!x64() && result == INVALID_SOCKET_32) {
        result = INVALID_SOCKET;
    }
    return result;
}

const std::string& WSASocketA::function_name() const { return FunctionName; }
const std::string& WSASocketA::library_name() const { return LibraryName; }
void WSASocketA::write(std::ostream& os) const {
    boost::io::ios_flags_saver ifs(os);
    // TODO
}

WSASocketA::WSASocketA(Event& event) : WindowsFunctionCall(event, ArgumentCount) {
    af_ = get_argument(0);
    type_ = get_argument(1);
    protocol_ = get_argument(2);
    lpProtocolInfo_ = get_address_argument(3);
    g_ = get_argument(4);
    dwFlags_ = get_argument(5);
}

WSASocketA::~WSASocketA() = default;

} // namespace ws2_32
} // namespace windows
} // namespace introvirt