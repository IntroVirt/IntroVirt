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
#include <introvirt/windows/kernel/nt/types/access_mask/ACCESS_MASK.hh>
#include <sstream>

namespace introvirt {
namespace windows {
namespace nt {

const std::string& to_string(AccessMaskFlag flag) {
    static const std::string DELETE_STR("DELETE");
    static const std::string READ_CONTROL_STR("READ_CONTROL");
    static const std::string WRITE_DAC_STR("WRITE_DAC");
    static const std::string WRITE_OWNER_STR("WRITE_OWNER");
    static const std::string SYNCHRONIZE_STR("SYNCHRONIZE");
    static const std::string STANDARD_RIGHTS_ALL_STR("STANDARD_RIGHTS_ALL");
    static const std::string STANDARD_RIGHTS_REQUIRED_STR("STANDARD_RIGHTS_REQUIRED");
    static const std::string ACCESS_SYSTEM_SECURITY_STR("ACCESS_SYSTEM_SECURITY");
    static const std::string GENERIC_ALL_STR("GENERIC_ALL");
    static const std::string GENERIC_EXECUTE_STR("GENERIC_EXECUTE");
    static const std::string GENERIC_WRITE_STR("GENERIC_WRITE");
    static const std::string GENERIC_READ_STR("GENERIC_READ");
    static const std::string MAXIMUM_ALLOWED_STR("MAXIMUM_ALLOWED");
    static const std::string UNKNOWN_STR("UNKNOWN");

    switch (flag) {
    case AccessMaskFlag::DELETE:
        return DELETE_STR;
    case AccessMaskFlag::READ_CONTROL:
        return READ_CONTROL_STR;
    case AccessMaskFlag::WRITE_DAC:
        return WRITE_DAC_STR;
    case AccessMaskFlag::WRITE_OWNER:
        return WRITE_OWNER_STR;
    case AccessMaskFlag::SYNCHRONIZE:
        return SYNCHRONIZE_STR;
    case AccessMaskFlag::STANDARD_RIGHTS_ALL:
        return STANDARD_RIGHTS_ALL_STR;
    case AccessMaskFlag::STANDARD_RIGHTS_REQUIRED:
        return STANDARD_RIGHTS_REQUIRED_STR;
    case AccessMaskFlag::ACCESS_SYSTEM_SECURITY:
        return ACCESS_SYSTEM_SECURITY_STR;
    case AccessMaskFlag::GENERIC_ALL:
        return GENERIC_ALL_STR;
    case AccessMaskFlag::GENERIC_EXECUTE:
        return GENERIC_EXECUTE_STR;
    case AccessMaskFlag::GENERIC_WRITE:
        return GENERIC_WRITE_STR;
    case AccessMaskFlag::GENERIC_READ:
        return GENERIC_READ_STR;
    case AccessMaskFlag::MAXIMUM_ALLOWED:
        return MAXIMUM_ALLOWED_STR;
    }

    return UNKNOWN_STR;
}

std::ostream& operator<<(std::ostream& os, AccessMaskFlag flag) {
    os << to_string(flag);
    return os;
}

std::string to_string(ACCESS_MASK mask) {
    std::ostringstream ss;
    ss << mask;
    return ss.str();
}

#define WRITE_IF_ENABLED(flag)                                                                     \
    if (mask.has(flag)) {                                                                          \
        os << to_string(flag) << ' ';                                                              \
    }

std::ostream& operator<<(std::ostream& os, ACCESS_MASK mask) {
    WRITE_IF_ENABLED(AccessMaskFlag::STANDARD_RIGHTS_ALL);
    /* We don't do STANDARD_RIGHTS_READ/WRITE/EXECUTE here,
       because they're all just defined as READ_CONTROL */

    WRITE_IF_ENABLED(AccessMaskFlag::DELETE);
    WRITE_IF_ENABLED(AccessMaskFlag::READ_CONTROL);
    WRITE_IF_ENABLED(AccessMaskFlag::WRITE_DAC);
    WRITE_IF_ENABLED(AccessMaskFlag::WRITE_OWNER);
    WRITE_IF_ENABLED(AccessMaskFlag::SYNCHRONIZE);
    WRITE_IF_ENABLED(AccessMaskFlag::ACCESS_SYSTEM_SECURITY);
    WRITE_IF_ENABLED(AccessMaskFlag::GENERIC_ALL);
    WRITE_IF_ENABLED(AccessMaskFlag::GENERIC_EXECUTE);
    WRITE_IF_ENABLED(AccessMaskFlag::GENERIC_WRITE);
    WRITE_IF_ENABLED(AccessMaskFlag::GENERIC_READ);
    WRITE_IF_ENABLED(AccessMaskFlag::MAXIMUM_ALLOWED);
    return os;
}

} /* namespace nt */
} /* namespace windows */
} /* namespace introvirt */
