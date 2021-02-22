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
#include "LUID_AND_ATTRIBUTES_IMPL.hh"

#include <boost/io/ios_state.hpp>

namespace introvirt {
namespace windows {
namespace nt {

LUID_AND_ATTRIBUTES_IMPL::LUID_AND_ATTRIBUTES_IMPL(const GuestVirtualAddress& gva)
    : gva_(gva), luid_(gva), luid_and_attributes_(gva) {}

std::unique_ptr<LUID_AND_ATTRIBUTES>
LUID_AND_ATTRIBUTES::make_unique(const GuestVirtualAddress& gva) {
    return std::make_unique<LUID_AND_ATTRIBUTES_IMPL>(gva);
}

std::shared_ptr<LUID_AND_ATTRIBUTES>
LUID_AND_ATTRIBUTES::make_shared(const GuestVirtualAddress& gva) {
    return std::make_shared<LUID_AND_ATTRIBUTES_IMPL>(gva);
}

const std::string& to_string(LUID_ATTRIBUTE_FLAGS flag) {
    static const std::string SE_PRIVILEGE_ENABLED_BY_DEFAULT_STR("SE_PRIVILEGE_ENABLED_BY_DEFAULT");
    static const std::string SE_PRIVILEGE_ENABLED_STR("SE_PRIVILEGE_ENABLED");
    static const std::string SE_PRIVILEGE_REMOVED_STR("SE_PRIVILEGE_REMOVED");
    static const std::string SE_PRIVILEGE_USED_FOR_ACCESS_STR("SE_PRIVILEGE_USED_FOR_ACCESS");
    static const std::string UNKNOWN_STR("UNKNOWN");

    switch (flag) {
    case LUID_ATTRIBUTE_FLAGS::SE_PRIVILEGE_ENABLED_BY_DEFAULT:
        return SE_PRIVILEGE_ENABLED_BY_DEFAULT_STR;
    case LUID_ATTRIBUTE_FLAGS::SE_PRIVILEGE_ENABLED:
        return SE_PRIVILEGE_ENABLED_STR;
    case LUID_ATTRIBUTE_FLAGS::SE_PRIVILEGE_REMOVED:
        return SE_PRIVILEGE_REMOVED_STR;
    case LUID_ATTRIBUTE_FLAGS::SE_PRIVILEGE_USED_FOR_ACCESS:
        return SE_PRIVILEGE_USED_FOR_ACCESS_STR;
    }

    return UNKNOWN_STR;
}
std::ostream& operator<<(std::ostream& os, LUID_ATTRIBUTE_FLAGS flag) {
    os << to_string(flag);
    return os;
}

std::string to_string(LUID_ATTRIBUTES atts) {
    std::stringstream ss;
    ss << atts;
    return ss.str();
}

std::ostream& operator<<(std::ostream& os, LUID_ATTRIBUTES atts) {
    uint32_t value = atts.value();

    if (value & LUID_ATTRIBUTE_FLAGS::SE_PRIVILEGE_ENABLED_BY_DEFAULT) {
        os << LUID_ATTRIBUTE_FLAGS::SE_PRIVILEGE_ENABLED_BY_DEFAULT;
        value &= ~LUID_ATTRIBUTE_FLAGS::SE_PRIVILEGE_ENABLED_BY_DEFAULT;
        if (value != 0)
            os << " | ";
    }

    if (value & LUID_ATTRIBUTE_FLAGS::SE_PRIVILEGE_ENABLED) {
        os << LUID_ATTRIBUTE_FLAGS::SE_PRIVILEGE_ENABLED;
        value &= ~LUID_ATTRIBUTE_FLAGS::SE_PRIVILEGE_ENABLED;
        if (value != 0)
            os << " | ";
    }

    if (value & LUID_ATTRIBUTE_FLAGS::SE_PRIVILEGE_REMOVED) {
        os << LUID_ATTRIBUTE_FLAGS::SE_PRIVILEGE_REMOVED;
        value &= ~LUID_ATTRIBUTE_FLAGS::SE_PRIVILEGE_REMOVED;
        if (value != 0)
            os << " | ";
    }

    if (value & LUID_ATTRIBUTE_FLAGS::SE_PRIVILEGE_USED_FOR_ACCESS) {
        os << LUID_ATTRIBUTE_FLAGS::SE_PRIVILEGE_USED_FOR_ACCESS;
        value &= ~LUID_ATTRIBUTE_FLAGS::SE_PRIVILEGE_USED_FOR_ACCESS;
        if (value != 0)
            os << " | ";
    }

    if (value) {
        boost::io::ios_flags_saver ifs(os);
        os << " UNKNOWN(0x" << std::hex << value << ")";
    }

    return os;
}

} /* namespace nt */
} /* namespace windows */
} /* namespace introvirt */
