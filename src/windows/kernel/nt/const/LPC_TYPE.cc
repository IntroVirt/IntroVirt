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

#include <introvirt/windows/kernel/nt/const/LPC_TYPE.hh>

namespace introvirt {
namespace windows {
namespace nt {

const std::string& to_string(LPC_TYPE infoClass) {
    static const std::string LPC_REQUEST("LPC_REQUEST");
    static const std::string LPC_REPLY("LPC_REPLY");
    static const std::string LPC_DATAGRAM("LPC_DATAGRAM");
    static const std::string LPC_LOST_REPLY("LPC_LOST_REPLY");
    static const std::string LPC_PORT_CLOSED("LPC_PORT_CLOSED");
    static const std::string LPC_CLIENT_DIED("LPC_CLIENT_DIED");
    static const std::string LPC_EXCEPTION("LPC_EXCEPTION");
    static const std::string LPC_DEBUG_EVENT("LPC_DEBUG_EVENT");
    static const std::string LPC_ERROR_EVENT("LPC_ERROR_EVENT");
    static const std::string LPC_CONNECTION_REQUEST("LPC_CONNECTION_REQUEST");
    static const std::string LPC_UNKNOWN_MESSAGE_TYPE("LPC_UNKNOWN_MESSAGE_TYPE");

    switch (infoClass) {
    case LPC_TYPE::LPC_REQUEST:
        return LPC_REQUEST;
    case LPC_TYPE::LPC_REPLY:
        return LPC_REPLY;
    case LPC_TYPE::LPC_DATAGRAM:
        return LPC_DATAGRAM;
    case LPC_TYPE::LPC_LOST_REPLY:
        return LPC_LOST_REPLY;
    case LPC_TYPE::LPC_PORT_CLOSED:
        return LPC_PORT_CLOSED;
    case LPC_TYPE::LPC_CLIENT_DIED:
        return LPC_CLIENT_DIED;
    case LPC_TYPE::LPC_EXCEPTION:
        return LPC_EXCEPTION;
    case LPC_TYPE::LPC_DEBUG_EVENT:
        return LPC_DEBUG_EVENT;
    case LPC_TYPE::LPC_ERROR_EVENT:
        return LPC_ERROR_EVENT;
    case LPC_TYPE::LPC_CONNECTION_REQUEST:
        return LPC_CONNECTION_REQUEST;
    case LPC_TYPE::LPC_UNKNOWN_MESSAGE_TYPE:
        break;
    }

    return LPC_UNKNOWN_MESSAGE_TYPE;
}

std::ostream& operator<<(std::ostream& os, LPC_TYPE cid) {
    os << to_string(cid);
    return os;
}

} /* namespace nt */
} /* namespace windows */
} /* namespace introvirt */
