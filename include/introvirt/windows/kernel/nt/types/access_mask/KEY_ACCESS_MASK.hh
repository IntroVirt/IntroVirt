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
 * @brief Valid flags for KEY_ACCESS_MASK
 *
 * <a
 * href="https://docs.microsoft.com/en-us/windows/win32/sysinfo/registry-key-security-and-access-rights">MSDN
 * Article</a>
 *
 * @see KEY_ACCESS_MASK
 */
enum KeyAccessMaskFlag {
    /// Required to query the values of a registry key.
    KEY_QUERY_VALUE = 0x001,
    /// Required to create, delete, or set a registry value.
    KEY_SET_VALUE = 0x002,
    /// Required to create a subkey of a registry key.
    KEY_CREATE_SUB_KEY = 0x004,
    /// Required to enumerate the subkeys of a registry key.
    KEY_ENUMERATE_SUB_KEYS = 0x008,
    /// Required to request change notifications for a registry key or for subkeys of a registry
    /// key.
    KEY_NOTIFY = 0x010,
    /// Reserved for system use
    KEY_CREATE_LINK = 0x020,
    /// Indicates that an application on 64-bit Windows should operate on the 64-bit registry view.
    KEY_WOW64_64KEY = 0x100,
    /// Indicates that an application on 64-bit Windows should operate on the 32-bit registry view.
    KEY_WOW64_32KEY = 0x200,

    /// Combines the STANDARD_RIGHTS_READ, KEY_QUERY_VALUE, KEY_ENUMERATE_SUB_KEYS, and KEY_NOTIFY
    /// values.
    KEY_READ = 0x20019,
    /// Combines the STANDARD_RIGHTS_WRITE, KEY_SET_VALUE, and KEY_CREATE_SUB_KEY access rights.
    KEY_WRITE = 0x20006,
    /// Equivalent to KEY_READ.
    KEY_EXECUTE = KEY_READ,
    /// Combines the STANDARD_RIGHTS_REQUIRED, KEY_QUERY_VALUE, KEY_SET_VALUE, KEY_CREATE_SUB_KEY,
    /// KEY_ENUMERATE_SUB_KEYS, KEY_NOTIFY, and KEY_CREATE_LINK access rights.
    KEY_ALL_ACCESS = 0xF003F,
};

/**
 * @brief ACCESS_MASK class for key permissions
 *
 * @see KeyAccessMaskFlag
 */
class KEY_ACCESS_MASK final : public ACCESS_MASK {
  public:
    /**
     * @brief Check if the given flag is enabled
     *
     * @param flag
     * @return true
     * @return false
     */
    bool has(KeyAccessMaskFlag flag) const { return (value() & flag) == flag; }

    /**
     * @brief Set the state of the given flag to enabled
     *
     * @param flag The flag to enable
     */
    void set(KeyAccessMaskFlag flag) { value(value() | flag); }

    /**
     * @brief Clear the given flag
     *
     * @param flag The flag to clear
     */
    void clear(KeyAccessMaskFlag flag) { value(value() & ~flag); }

    AccessMaskType type() const override { return KeyAccessMask; }

    // Constructors and assignment operators
    KEY_ACCESS_MASK() = default;
    KEY_ACCESS_MASK(uint32_t mask) : ACCESS_MASK(mask) {}

    KEY_ACCESS_MASK(const KEY_ACCESS_MASK&) = default;
    KEY_ACCESS_MASK& operator=(const KEY_ACCESS_MASK&) = default;
};

const std::string& to_string(KeyAccessMaskFlag);
std::ostream& operator<<(std::ostream&, KeyAccessMaskFlag);

std::string to_string(KEY_ACCESS_MASK);
std::ostream& operator<<(std::ostream&, KEY_ACCESS_MASK);

} /* namespace nt */
} /* namespace windows */
} /* namespace introvirt */
