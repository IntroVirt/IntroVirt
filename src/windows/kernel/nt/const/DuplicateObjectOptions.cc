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

#include <introvirt/windows/kernel/nt/const/DuplicateObjectOptions.hh>

#include <sstream>

namespace introvirt {
namespace windows {
namespace nt {

DuplicateObjectOptions::DuplicateObjectOptions(uint32_t value) : value(value) {}

uint32_t DuplicateObjectOptions::get() const { return value; }

DuplicateObjectOptions::operator uint32_t() const { return value; }

bool DuplicateObjectOptions::isFlagEnabled(int flag) const { return (value & flag) != 0u; }

void DuplicateObjectOptions::setFlag(int flag, bool enabled) {
    if (enabled) {
        value |= flag;
    } else {
        value &= ~flag;
    }
}

std::string DuplicateObjectOptions::to_string(const std::string& separator) const {
    std::ostringstream result;

    if ((value & DuplicateObjectOptions::DUPLICATE_CLOSE_SOURCE) != 0u) {
        result << "DUPLICATE_CLOSE_SOURCE" << separator;
    }
    if ((value & DuplicateObjectOptions::DUPLICATE_SAME_ACCESS) != 0u) {
        result << "DUPLICATE_CLOSE_SOURCE" << separator;
    }
    if ((value & DuplicateObjectOptions::DUPLICATE_SAME_ATTRIBUTES) != 0u) {
        result << "DUPLICATE_SAME_ATTRIBUTES" << separator;
    }

    return result.str();
}

std::string to_string(const DuplicateObjectOptions& options, const std::string& separator) {
    return options.to_string(separator);
}

} /* namespace nt */
} /* namespace windows */
} /* namespace introvirt */
