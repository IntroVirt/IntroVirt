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
 * @brief Valid flags for SECTION_ACCESS_MASK
 *
 * @see SECTION_ACCESS_MASK
 */
enum SectionAccessMaskFlag {
    /// Query the section object for information about the section. Drivers should set this flag.
    SECTION_QUERY = 0x001,
    /// Write views of the section.
    SECTION_MAP_WRITE = 0x002,
    /// Read views of the section.
    SECTION_MAP_READ = 0x004,
    /// Execute views of the section.
    SECTION_MAP_EXECUTE = 0x008,
    /// Dynamically extend the size of the section.
    SECTION_EXTEND_SIZE = 0x010,
    SECTION_MAP_EXECUTE_EXPLICIT = 0x020,

    /// All permissions combined with STANDARD_RIGHTS_REQUIRED
    SECTION_ALL_ACCESS = 0xf001f
};

/**
 * @brief ACCESS_MASK class for section permissions
 *
 * @see SectionAccessMaskFlag
 */
class SECTION_ACCESS_MASK final : public ACCESS_MASK {
  public:
    /**
     * @brief Check if the given flag is enabled
     *
     * @param flag
     * @return true
     * @return false
     */
    bool has(SectionAccessMaskFlag flag) const { return (value() & flag) == flag; }

    /**
     * @brief Set the state of the given flag to enabled
     *
     * @param flag The flag to enable
     */
    void set(SectionAccessMaskFlag flag) { value(value() | flag); }

    /**
     * @brief Clear the given flag
     *
     * @param flag The flag to clear
     */
    void clear(SectionAccessMaskFlag flag) { value(value() & ~flag); }

    AccessMaskType type() const override { return SectionAccessMask; }

    // Constructors and assignment operators
    SECTION_ACCESS_MASK() = default;
    SECTION_ACCESS_MASK(uint32_t mask) : ACCESS_MASK(mask) {}

    SECTION_ACCESS_MASK(const SECTION_ACCESS_MASK&) = default;
    SECTION_ACCESS_MASK& operator=(const SECTION_ACCESS_MASK&) = default;
};

const std::string& to_string(SectionAccessMaskFlag);
std::ostream& operator<<(std::ostream&, SectionAccessMaskFlag);

std::string to_string(SECTION_ACCESS_MASK);
std::ostream& operator<<(std::ostream&, SECTION_ACCESS_MASK);

} /* namespace nt */
} /* namespace windows */
} /* namespace introvirt */
