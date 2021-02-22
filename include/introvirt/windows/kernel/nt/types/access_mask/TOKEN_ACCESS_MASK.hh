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
#pragma once

#include "ACCESS_MASK.hh"

namespace introvirt {
namespace windows {
namespace nt {

/**
 * @brief Valid flags for TOKEN_ACCESS_MASK
 *
 * <a
 * href="https://docs.microsoft.com/en-us/windows/win32/secauthz/access-rights-for-access-token-objects">MSDN
 * Article</a>
 *
 * @see TOKEN_ACCESS_MASK
 */
enum TokenAccessMaskFlag {
    /// Required to attach a primary token to a process. The SE_ASSIGNPRIMARYTOKEN_NAME privilege is
    /// also required to accomplish this task.
    TOKEN_ASSIGN_PRIMARY = 0x0001,
    /// Required to duplicate an access token.
    TOKEN_DUPLICATE = 0x0002,
    /// Required to attach an impersonation access token to a process.
    TOKEN_IMPERSONATE = 0x0004,
    /// Required to query an access token.
    TOKEN_QUERY = 0x0008,
    /// Required to query the source of an access token.
    TOKEN_QUERY_SOURCE = 0x0010,
    /// Required to enable or disable the privileges in an access token.
    TOKEN_ADJUST_PRIVILEGES = 0x0020,
    /// Required to adjust the attributes of the groups in an access token.
    TOKEN_ADJUST_GROUPS = 0x0040,
    /// Required to change the default owner, primary group, or DACL of an access token.
    TOKEN_ADJUST_DEFAULT = 0x0080,
    /// Required to adjust the session ID of an access token. The SE_TCB_NAME privilege is required.
    TOKEN_ADJUST_SESSIONID = 0x0100,
    /// Combines STANDARD_RIGHTS_READ and TOKEN_QUERY.
    TOKEN_READ = STANDARD_RIGHTS_READ | TOKEN_QUERY,
    /// Combines STANDARD_RIGHTS_READ and TOKEN_QUERY.
    TOKEN_WRITE = STANDARD_RIGHTS_WRITE | TOKEN_ADJUST_PRIVILEGES | TOKEN_ADJUST_GROUPS |
                  TOKEN_ADJUST_DEFAULT,
    /// All possible access rights for a token.
    TOKEN_ALL_ACCESS = 0xF01FF,
};

/**
 * @brief ACCESS_MASK class for token permissions
 *
 * @see TokenAccessMaskFlag
 */
class TOKEN_ACCESS_MASK final : public ACCESS_MASK {
  public:
    /**
     * @brief Check if the given flag is enabled
     *
     * @param flag
     * @return true
     * @return false
     */
    bool has(TokenAccessMaskFlag flag) const { return (value() & flag) == flag; }

    /**
     * @brief Set the state of the given flag to enabled
     *
     * @param flag The flag to enable
     */
    void set(TokenAccessMaskFlag flag) { value(value() | flag); }

    /**
     * @brief Clear the given flag
     *
     * @param flag The flag to clear
     */
    void clear(TokenAccessMaskFlag flag) { value(value() & ~flag); }

    AccessMaskType type() const override { return TokenAccessMask; }

    // Constructors and assignment operators
    TOKEN_ACCESS_MASK() = default;
    TOKEN_ACCESS_MASK(uint32_t mask) : ACCESS_MASK(mask) {}

    TOKEN_ACCESS_MASK(const TOKEN_ACCESS_MASK&) = default;
    TOKEN_ACCESS_MASK& operator=(const TOKEN_ACCESS_MASK&) = default;
};

const std::string& to_string(TokenAccessMaskFlag);
std::ostream& operator<<(std::ostream&, TokenAccessMaskFlag);

std::string to_string(TOKEN_ACCESS_MASK);
std::ostream& operator<<(std::ostream&, TOKEN_ACCESS_MASK);

} /* namespace nt */
} /* namespace windows */
} /* namespace introvirt */
