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
#include <introvirt/windows/kernel/nt/const/ProcessCreateFlags.hh>
#include <sstream>

namespace introvirt {
namespace windows {
namespace nt {

std::string ProcessCreateFlags::to_string(const std::string& separator) const {
    std::ostringstream result;

    if ((value_ & ProcessCreateFlag::BREAKAWAY) != 0u) {
        result << "BREAKAWAY" << separator;
    }
    if ((value_ & ProcessCreateFlag::NO_DEBUG_INHERIT) != 0u) {
        result << "NO_DEBUG_INHERIT" << separator;
    }
    if ((value_ & ProcessCreateFlag::INHERIT_HANDLES) != 0u) {
        result << "INHERIT_HANDLES" << separator;
    }
    if ((value_ & ProcessCreateFlag::OVERRIDE_ADDRESS_SPACE) != 0u) {
        result << "OVERRIDE_ADDRESS_SPACE" << separator;
    }
    if ((value_ & ProcessCreateFlag::LARGE_PAGES) != 0u) {
        result << "LARGE_PAGES" << separator;
    }

    std::string resultStr = result.str();

    // Remove the trailing separator if one exists
    if (!resultStr.empty() != 0u) {
        return resultStr.substr(0, resultStr.size() - separator.size());
    }

    return resultStr;
}

std::string to_string(ProcessCreateFlags options, const std::string& separator) {
    return options.to_string(separator);
}

std::ostream& operator<<(std::ostream& os, ProcessCreateFlags flags) {
    os << to_string(flags);
    return os;
}

} /* namespace nt */
} /* namespace windows */
} /* namespace introvirt */
