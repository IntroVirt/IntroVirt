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

#include <introvirt/windows/kernel/nt/const/FILE_SHARE_ACCESS.hh>

#include <sstream>

namespace introvirt {
namespace windows {
namespace nt {

std::string FILE_SHARE_ACCESS::to_string(const std::string& separator) const {
    std::ostringstream result;

    if ((value_ & FILE_SHARE_ACCESS_FLAG::FILE_SHARE_READ) != 0u) {
        result << "FILE_SHARE_READ" << separator;
    }
    if ((value_ & FILE_SHARE_ACCESS_FLAG::FILE_SHARE_WRITE) != 0u) {
        result << "FILE_SHARE_WRITE" << separator;
    }
    if ((value_ & FILE_SHARE_ACCESS_FLAG::FILE_SHARE_DELETE) != 0u) {
        result << "FILE_SHARE_DELETE" << separator;
    }

    std::string resultStr = result.str();

    // Remove the trailing separator if one exists
    if (!resultStr.empty() != 0u) {
        return resultStr.substr(0, resultStr.size() - separator.size());
    }

    return resultStr;
}

std::string to_string(FILE_SHARE_ACCESS options, const std::string& separator) {
    return options.to_string(separator);
}

std::ostream& operator<<(std::ostream& os, FILE_SHARE_ACCESS options) {
    os << to_string(options);
    return os;
}

} /* namespace nt */
} /* namespace windows */
} /* namespace introvirt */
