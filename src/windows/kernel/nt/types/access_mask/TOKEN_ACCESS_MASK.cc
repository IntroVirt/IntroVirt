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
#include <introvirt/windows/kernel/nt/types/access_mask/TOKEN_ACCESS_MASK.hh>
#include <sstream>

namespace introvirt {
namespace windows {
namespace nt {

const std::string& to_string(TokenAccessMaskFlag flag) {
    static const std::string TOKEN_ASSIGN_PRIMARY_STR("TOKEN_ASSIGN_PRIMARY");
    static const std::string TOKEN_DUPLICATE_STR("TOKEN_DUPLICATE");
    static const std::string TOKEN_IMPERSONATE_STR("TOKEN_IMPERSONATE");
    static const std::string TOKEN_QUERY_STR("TOKEN_QUERY");
    static const std::string TOKEN_QUERY_SOURCE_STR("TOKEN_QUERY_SOURCE");
    static const std::string TOKEN_ADJUST_PRIVILEGES_STR("TOKEN_ADJUST_PRIVILEGES");
    static const std::string TOKEN_ADJUST_GROUPS_STR("TOKEN_ADJUST_GROUPS");
    static const std::string TOKEN_ADJUST_DEFAULT_STR("TOKEN_ADJUST_DEFAULT");
    static const std::string TOKEN_ADJUST_SESSIONID_STR("TOKEN_ADJUST_SESSIONID");
    static const std::string TOKEN_READ_STR("TOKEN_READ");
    static const std::string TOKEN_WRITE_STR("TOKEN_WRITE");
    static const std::string TOKEN_ALL_ACCESS_STR("TOKEN_ALL_ACCESS");
    const static std::string UNKNOWN_STR("UNKNOWN");

    switch (flag) {
    case TokenAccessMaskFlag::TOKEN_ASSIGN_PRIMARY:
        return TOKEN_ASSIGN_PRIMARY_STR;
    case TokenAccessMaskFlag::TOKEN_DUPLICATE:
        return TOKEN_DUPLICATE_STR;
    case TokenAccessMaskFlag::TOKEN_IMPERSONATE:
        return TOKEN_IMPERSONATE_STR;
    case TokenAccessMaskFlag::TOKEN_QUERY:
        return TOKEN_QUERY_STR;
    case TokenAccessMaskFlag::TOKEN_QUERY_SOURCE:
        return TOKEN_QUERY_SOURCE_STR;
    case TokenAccessMaskFlag::TOKEN_ADJUST_PRIVILEGES:
        return TOKEN_ADJUST_PRIVILEGES_STR;
    case TokenAccessMaskFlag::TOKEN_ADJUST_GROUPS:
        return TOKEN_ADJUST_GROUPS_STR;
    case TokenAccessMaskFlag::TOKEN_ADJUST_DEFAULT:
        return TOKEN_ADJUST_DEFAULT_STR;
    case TokenAccessMaskFlag::TOKEN_ADJUST_SESSIONID:
        return TOKEN_ADJUST_SESSIONID_STR;
    case TokenAccessMaskFlag::TOKEN_READ:
        return TOKEN_READ_STR;
    case TokenAccessMaskFlag::TOKEN_WRITE:
        return TOKEN_WRITE_STR;
    case TokenAccessMaskFlag::TOKEN_ALL_ACCESS:
        return TOKEN_ALL_ACCESS_STR;
    }

    return UNKNOWN_STR;
}

std::ostream& operator<<(std::ostream& os, TokenAccessMaskFlag flag) {
    os << to_string(flag);
    return os;
}

std::string to_string(TOKEN_ACCESS_MASK mask) {
    std::ostringstream ss;
    ss << mask;
    return ss.str();
}

#define WRITE_IF_ENABLED(flag)                                                                     \
    if (mask.has(flag)) {                                                                          \
        os << to_string(flag) << ' ';                                                              \
        mask.clear(flag);                                                                          \
    }

std::ostream& operator<<(std::ostream& os, TOKEN_ACCESS_MASK mask) {
    WRITE_IF_ENABLED(TokenAccessMaskFlag::TOKEN_ALL_ACCESS);
    WRITE_IF_ENABLED(TokenAccessMaskFlag::TOKEN_READ);
    WRITE_IF_ENABLED(TokenAccessMaskFlag::TOKEN_WRITE);

    WRITE_IF_ENABLED(TokenAccessMaskFlag::TOKEN_ASSIGN_PRIMARY);
    WRITE_IF_ENABLED(TokenAccessMaskFlag::TOKEN_DUPLICATE);
    WRITE_IF_ENABLED(TokenAccessMaskFlag::TOKEN_IMPERSONATE);
    WRITE_IF_ENABLED(TokenAccessMaskFlag::TOKEN_QUERY);
    WRITE_IF_ENABLED(TokenAccessMaskFlag::TOKEN_QUERY_SOURCE);
    WRITE_IF_ENABLED(TokenAccessMaskFlag::TOKEN_ADJUST_PRIVILEGES);
    WRITE_IF_ENABLED(TokenAccessMaskFlag::TOKEN_ADJUST_GROUPS);
    WRITE_IF_ENABLED(TokenAccessMaskFlag::TOKEN_ADJUST_DEFAULT);
    WRITE_IF_ENABLED(TokenAccessMaskFlag::TOKEN_ADJUST_SESSIONID);

    // Now call the base class to handle any remaining bits
    ACCESS_MASK base(mask.value());
    os << base;

    return os;
}

} /* namespace nt */
} /* namespace windows */
} /* namespace introvirt */
