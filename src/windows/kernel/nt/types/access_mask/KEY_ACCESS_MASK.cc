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
#include <introvirt/windows/kernel/nt/types/access_mask/KEY_ACCESS_MASK.hh>
#include <sstream>

namespace introvirt {
namespace windows {
namespace nt {

const std::string& to_string(KeyAccessMaskFlag flag) {
    static const std::string KEY_QUERY_VALUE_STR("KEY_QUERY_VALUE");
    static const std::string KEY_SET_VALUE_STR("KEY_SET_VALUE");
    static const std::string KEY_CREATE_SUB_KEY_STR("KEY_CREATE_SUB_KEY");
    static const std::string KEY_ENUMERATE_SUB_KEYS_STR("KEY_ENUMERATE_SUB_KEYS");
    static const std::string KEY_NOTIFY_STR("KEY_NOTIFY");
    static const std::string KEY_CREATE_LINK_STR("KEY_CREATE_LINK");
    static const std::string KEY_WOW64_64KEY_STR("KEY_WOW64_64KEY");
    static const std::string KEY_WOW64_32KEY_STR("KEY_WOW64_32KEY");
    static const std::string KEY_READ_STR("KEY_READ");
    static const std::string KEY_WRITE_STR("KEY_WRITE");
    static const std::string KEY_ALL_ACCESS_STR("KEY_ALL_ACCESS");
    const static std::string UNKNOWN_STR("UNKNOWN");

    switch (flag) {
    case KeyAccessMaskFlag::KEY_QUERY_VALUE:
        return KEY_QUERY_VALUE_STR;
    case KeyAccessMaskFlag::KEY_SET_VALUE:
        return KEY_SET_VALUE_STR;
    case KeyAccessMaskFlag::KEY_CREATE_SUB_KEY:
        return KEY_CREATE_SUB_KEY_STR;
    case KeyAccessMaskFlag::KEY_ENUMERATE_SUB_KEYS:
        return KEY_ENUMERATE_SUB_KEYS_STR;
    case KeyAccessMaskFlag::KEY_NOTIFY:
        return KEY_NOTIFY_STR;
    case KeyAccessMaskFlag::KEY_WOW64_64KEY:
        return KEY_WOW64_64KEY_STR;
    case KeyAccessMaskFlag::KEY_WOW64_32KEY:
        return KEY_WOW64_32KEY_STR;
    case KeyAccessMaskFlag::KEY_READ:
        return KEY_READ_STR;
    case KeyAccessMaskFlag::KEY_WRITE:
        return KEY_WRITE_STR;
    case KeyAccessMaskFlag::KEY_CREATE_LINK:
        return KEY_CREATE_LINK_STR;
    case KeyAccessMaskFlag::KEY_ALL_ACCESS:
        return KEY_ALL_ACCESS_STR;
    }

    return UNKNOWN_STR;
}

std::ostream& operator<<(std::ostream& os, KeyAccessMaskFlag flag) {
    os << to_string(flag);
    return os;
}

std::string to_string(KEY_ACCESS_MASK mask) {
    std::ostringstream ss;
    ss << mask;
    return ss.str();
}

#define WRITE_IF_ENABLED(flag)                                                                     \
    if (mask.has(flag)) {                                                                          \
        os << to_string(flag) << ' ';                                                              \
        mask.clear(flag);                                                                          \
    }

std::ostream& operator<<(std::ostream& os, KEY_ACCESS_MASK mask) {
    WRITE_IF_ENABLED(KeyAccessMaskFlag::KEY_ALL_ACCESS);
    WRITE_IF_ENABLED(KeyAccessMaskFlag::KEY_READ);
    WRITE_IF_ENABLED(KeyAccessMaskFlag::KEY_WRITE);

    WRITE_IF_ENABLED(KeyAccessMaskFlag::KEY_CREATE_LINK);
    WRITE_IF_ENABLED(KeyAccessMaskFlag::KEY_QUERY_VALUE);
    WRITE_IF_ENABLED(KeyAccessMaskFlag::KEY_SET_VALUE);
    WRITE_IF_ENABLED(KeyAccessMaskFlag::KEY_CREATE_SUB_KEY);
    WRITE_IF_ENABLED(KeyAccessMaskFlag::KEY_ENUMERATE_SUB_KEYS);
    WRITE_IF_ENABLED(KeyAccessMaskFlag::KEY_NOTIFY);
    WRITE_IF_ENABLED(KeyAccessMaskFlag::KEY_WOW64_64KEY);
    WRITE_IF_ENABLED(KeyAccessMaskFlag::KEY_WOW64_32KEY);

    // Now call the base class to handle any remaining bits
    ACCESS_MASK base(mask.value());
    os << base;

    return os;
}

} /* namespace nt */
} /* namespace windows */
} /* namespace introvirt */
