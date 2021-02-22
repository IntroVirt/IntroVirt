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

#include <introvirt/windows/kernel/nt/const/RegistryCreateOptions.hh>
#include <sstream>

namespace introvirt {
namespace windows {
namespace nt {

RegistryCreateOptions::RegistryCreateOptions() = default;
RegistryCreateOptions::RegistryCreateOptions(uint32_t value) : value(value) {}

uint32_t RegistryCreateOptions::getValue() const { return value; }
void RegistryCreateOptions::setValue(uint32_t value) { this->value = value; }
bool RegistryCreateOptions::isFlagEnabled(Flag flag) const {
    if (flag == REG_OPTION_NON_VOLATILE) {
        return !isFlagEnabled(REG_OPTION_VOLATILE);
    }

    return (value & flag) != 0u;
}
void RegistryCreateOptions::disableFlag(Flag flag) {
    if (flag == REG_OPTION_NON_VOLATILE) {
        enableFlag(REG_OPTION_VOLATILE);
    } else {
        value &= ~(static_cast<uint32_t>(flag));
    }
}
void RegistryCreateOptions::enableFlag(Flag flag) {
    if (flag == REG_OPTION_NON_VOLATILE) {
        disableFlag(REG_OPTION_VOLATILE);
    } else {
        value |= flag;
    }
}

std::string RegistryCreateOptions::to_string(const std::string& separator) const {
    std::ostringstream result;

    if ((value & RegistryCreateOptions::REG_OPTION_VOLATILE) != 0u) {
        result << "REG_OPTION_VOLATILE" << separator;
    } else {
        result << "REG_OPTION_NON_VOLATILE" << separator;
    }

    if ((value & RegistryCreateOptions::REG_OPTION_CREATE_LINK) != 0u) {
        result << "REG_OPTION_CREATE_LINK" << separator;
    }
    if ((value & RegistryCreateOptions::REG_OPTION_BACKUP_RESTORE) != 0u) {
        result << "REG_OPTION_BACKUP_RESTORE" << separator;
    }

    std::string resultStr = result.str();

    // Remove the trailing separator if one exists
    if (!resultStr.empty() != 0u) {
        return resultStr.substr(0, resultStr.size() - separator.size());
    }

    return resultStr;
}

RegistryCreateOptions::operator uint32_t() const { return value; }

RegistryCreateOptions::operator Json::Value() const { return value; }

std::string to_string(const RegistryCreateOptions& options, const std::string& separator) {
    return options.to_string(separator);
}

std::ostream& operator<<(std::ostream& os, const RegistryCreateOptions& options) {
    os << options.to_string();
    return os;
}

} /* namespace nt */
} /* namespace windows */
} /* namespace introvirt */
