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

#include <introvirt/util/json/json.hh>

#include <cstdint>
#include <ostream>
#include <string>

namespace introvirt {
namespace windows {
namespace nt {

/**
 * @brief Common flags for ACCESS_MASK
 *
 * <a href="https://docs.microsoft.com/en-us/windows/win32/secauthz/access-mask">MSDN Article</a>
 *
 * @see ACCESS_MASK
 */
enum AccessMaskFlag {
    /// Delete access
    DELETE = 0x010000,

    /// Read access to the owner, group, and discretionary access control list (DACL) of the
    /// security descriptor.
    READ_CONTROL = 0x020000,

    /// Write access to the DACL.
    WRITE_DAC = 0x040000,

    /// The right to change the owner in the object's security descriptor.
    WRITE_OWNER = 0x080000,

    /// The right to use the object for synchronization. This enables a
    /// thread to wait until the object is in the signaled state. Some object
    /// types do not support this access right.
    SYNCHRONIZE = 0x100000,

    /// Combines DELETE, READ_CONTROL, WRITE_DAC, WRITE_OWNER, and SYNCHRONIZE access.
    STANDARD_RIGHTS_ALL = DELETE | READ_CONTROL | WRITE_DAC | WRITE_OWNER | SYNCHRONIZE,

    /// Currently defined to equal READ_CONTROL.
    STANDARD_RIGHTS_READ = READ_CONTROL,

    /// Currently defined to equal READ_CONTROL.
    STANDARD_RIGHTS_WRITE = READ_CONTROL,

    /// Currently defined to equal READ_CONTROL.
    STANDARD_RIGHTS_EXECUTE = READ_CONTROL,

    /// Combines DELETE, READ_CONTROL, WRITE_DAC, and WRITE_OWNER access.
    STANDARD_RIGHTS_REQUIRED = DELETE | READ_CONTROL | WRITE_DAC | WRITE_OWNER,

    /// @brief used to indicate access to a system access control list (SACL)
    ACCESS_SYSTEM_SECURITY = 0x1000000,

    /// Generic all access
    GENERIC_ALL = 0x10000000,
    /// Generic execute access
    GENERIC_EXECUTE = 0x20000000,
    /// Generic write access
    GENERIC_WRITE = 0x40000000,
    /// Generic read access
    GENERIC_READ = 0x80000000,

    /// Reserve the maximum allowed permissions. If this bit is set, calls
    /// will succeed no matter what and Windows will allocate the maximum
    /// permissions.
    MAXIMUM_ALLOWED = 0x02000000,
};

/**
 * @brief Generic ACCESS_MASK type
 *
 * The ACCESS_MASK type has 16 bits reserved for specific types,
 * such as Token and File, but also a common 8 bits for "standard" rights,
 * and another 8 bits for other common fields.
 *
 * When possible, one of the more specific classes should be used.
 *
 * @see AccessMaskFlag
 *
 * @see DIR_ACCESS_MASK
 * @see EVENT_ACCESS_MASK
 * @see FILE_ACCESS_MASK
 * @see KEY_ACCESS_MASK
 * @see MUTANT_ACCESS_MASK
 * @see PROCESS_ACCESS_MASK
 * @see SECTION_ACCESS_MASK
 * @see THREAD_ACCESS_MASK
 * @see THREAD_ACCESS_MASK
 *
 */
class ACCESS_MASK {
  public:
    enum AccessMaskType {
        DirectoryAccessMask,
        EventAccessMask,
        FileAccessMask,
        KeyAccessMask,
        MutantAccessMask,
        ProcessAccessMask,
        SectionAccessMask,
        ThreadAccessMask,
        TokenAccessMask,
        UnknownAccessMaskType = -1
    };

    /**
     * @brief Get the type of access mask
     *
     * More specific classes override this.
     *
     * @return AccessMaskType
     */
    virtual AccessMaskType type() const { return UnknownAccessMaskType; }

    /**
     * @brief Get a JSON representation of the mask
     *
     * @return Json::Value
     */
    Json::Value json() const {
        Json::Value result;
        // TODO: Add in the actual flags (depends on type)
        result["value"] = value_;
        return result;
    }

    /**
     * @copydoc ACCESS_MASK::json() const
     */
    operator Json::Value() const { return json(); }

    /**
     * @brief Get the raw value
     *
     * @return uint32_t
     */
    inline uint32_t value() const { return value_; }

    /**
     * @copydoc ACCESS_MASK::value() const
     */
    inline operator uint32_t() const { return value_; }

    /**
     * @brief Set the raw value
     *
     * @param mask the mask to set
     */
    inline void value(uint32_t mask) { value_ = mask; }

    /**
     * @brief Check if the given flag is enabled
     *
     * @param flag The flag to check
     * @return true if the flag is set
     * @return false if the flag is not set
     */
    inline bool has(AccessMaskFlag flag) const { return (value() & flag) == flag; }

    /**
     * @brief Set the state of the given flag to enabled
     *
     * @param flag The flag to enable
     */
    inline void set(AccessMaskFlag flag) { value(value() | flag); }

    /**
     * @brief Clear the given flag
     *
     * @param flag The flag to clear
     */
    inline void clear(AccessMaskFlag flag) { value(value() & ~flag); }

    // Constructors and assignment operators
    ACCESS_MASK() = default;
    ACCESS_MASK(uint32_t mask) : value_(mask) {}

    ACCESS_MASK(const ACCESS_MASK&) = default;
    ACCESS_MASK& operator=(const ACCESS_MASK&) = default;

    virtual ~ACCESS_MASK() = default;

  private:
    uint32_t value_ = 0;
};

const std::string& to_string(AccessMaskFlag);
std::ostream& operator<<(std::ostream&, AccessMaskFlag);

std::string to_string(ACCESS_MASK);
std::ostream& operator<<(std::ostream&, ACCESS_MASK);

} // namespace nt
} // namespace windows
} // namespace introvirt
