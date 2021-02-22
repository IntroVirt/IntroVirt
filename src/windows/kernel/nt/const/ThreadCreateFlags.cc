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
#include <introvirt/windows/kernel/nt/const/ThreadCreateFlags.hh>

#include <sstream>

namespace introvirt {
namespace windows {
namespace nt {

std::string ThreadCreateFlags::to_string(const std::string& separator) const {
    std::ostringstream result;

    if ((value_ & ThreadCreateFlag::CREATE_SUSPENDED) != 0u) {
        result << "CREATE_SUSPENDED" << separator;
    }
    if ((value_ & ThreadCreateFlag::SKIP_THREAD_ATTACH) != 0u) {
        result << "SKIP_THREAD_ATTACH" << separator;
    }
    if ((value_ & ThreadCreateFlag::HIDE_FROM_DEBUGGER) != 0u) {
        result << "HIDE_FROM_DEBUGGER" << separator;
    }
    if ((value_ & ThreadCreateFlag::HAS_SECURITY_DESCRIPTOR) != 0u) {
        result << "HAS_SECURITY_DESCRIPTOR" << separator;
    }
    if ((value_ & ThreadCreateFlag::ACCESS_CHECK_IN_TARGET) != 0u) {
        result << "ACCESS_CHECK_IN_TARGET" << separator;
    }
    if ((value_ & ThreadCreateFlag::INITIAL_THREAD) != 0u) {
        result << "INITIAL_THREAD" << separator;
    }

    std::string resultStr = result.str();

    // Remove the trailing separator if one exists
    if (!resultStr.empty() != 0u) {
        return resultStr.substr(0, resultStr.size() - separator.size());
    }

    return resultStr;
}

std::string to_string(const ThreadCreateFlags& flags, const std::string& separator) {
    return flags.to_string(separator);
}

std::ostream& operator<<(std::ostream& os, const ThreadCreateFlags& flags) {
    os << flags.to_string();
    return os;
}

} /* namespace nt */
} /* namespace windows */
} /* namespace introvirt */
