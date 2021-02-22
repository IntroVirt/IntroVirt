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
 * @brief Valid flags for DIR_ACCESS_MASK
 *
 * <a href="https://docs.microsoft.com/en-us/windows/win32/devnotes/ntopendirectoryobject">MSDN
 * Article</a>
 *
 * @see DIR_ACCESS_MASK
 */
enum DirAccessMaskFlag {
    /// Query access to the directory object.
    DIRECTORY_QUERY = 0x0001,
    /// Name-lookup access to the directory object.
    DIRECTORY_TRAVERSE = 0x0002,
    /// Name-creation access to the directory object.
    DIRECTORY_CREATE_OBJECT = 0x0004,
    /// Subdirectory-creation access to the directory object.
    DIRECTORY_CREATE_SUBDIRECTORY = 0x0008,
    /// All of the preceding rights plus STANDARD_RIGHTS_REQUIRED.
    DIRECTORY_ALL_ACCESS = STANDARD_RIGHTS_REQUIRED | 0xF,
};

/**
 * @brief ACCESS_MASK class for directory permissions
 *
 * @see DirAccessMaskFlag
 */
class DIR_ACCESS_MASK final : public ACCESS_MASK {
  public:
    /**
     * @brief Check if the given flag is enabled
     *
     * @param flag
     * @return true
     * @return false
     */
    bool has(DirAccessMaskFlag flag) const { return (value() & flag) == flag; }

    /**
     * @brief Set the state of the given flag to enabled
     *
     * @param flag The flag to enable
     */
    void set(DirAccessMaskFlag flag) { value(value() | flag); }

    /**
     * @brief Clear the given flag
     *
     * @param flag The flag to clear
     */
    void clear(DirAccessMaskFlag flag) { value(value() & ~flag); }

    AccessMaskType type() const override { return DirectoryAccessMask; }

    // Constructors and assignment operators
    DIR_ACCESS_MASK() = default;
    DIR_ACCESS_MASK(uint32_t mask) : ACCESS_MASK(mask) {}

    DIR_ACCESS_MASK(const DIR_ACCESS_MASK&) = default;
    DIR_ACCESS_MASK& operator=(const DIR_ACCESS_MASK&) = default;
};

const std::string& to_string(DirAccessMaskFlag);
std::ostream& operator<<(std::ostream&, DirAccessMaskFlag);

std::string to_string(DIR_ACCESS_MASK);
std::ostream& operator<<(std::ostream&, DIR_ACCESS_MASK);

} /* namespace nt */
} /* namespace windows */
} /* namespace introvirt */
