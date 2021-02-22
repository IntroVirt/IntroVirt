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
 * @brief Valid flags for MUTANT_ACCESS_MASK
 *
 * @see MUTANT_ACCESS_MASK
 */
enum MutantAccessMaskFlag {
    MUTANT_QUERY_STATE = 0x0001,
    MUTANT_ALL_ACCESS = (STANDARD_RIGHTS_REQUIRED | SYNCHRONIZE | MUTANT_QUERY_STATE),
};

/**
 * @brief ACCESS_MASK class for mutant permissions
 *
 * @see MutantAccessMaskFlag
 */
class MUTANT_ACCESS_MASK final : public ACCESS_MASK {
  public:
    /**
     * @brief Check if the given flag is enabled
     *
     * @param flag
     * @return true
     * @return false
     */
    bool has(MutantAccessMaskFlag flag) const { return (value() & flag) == flag; }

    /**
     * @brief Set the state of the given flag to enabled
     *
     * @param flag The flag to enable
     */
    void set(MutantAccessMaskFlag flag) { value(value() | flag); }

    /**
     * @brief Clear the given flag
     *
     * @param flag The flag to clear
     */
    void clear(MutantAccessMaskFlag flag) { value(value() & ~flag); }

    AccessMaskType type() const override { return MutantAccessMask; }

    // Constructors and assignment operators
    MUTANT_ACCESS_MASK() = default;
    MUTANT_ACCESS_MASK(uint32_t mask) : ACCESS_MASK(mask) {}

    MUTANT_ACCESS_MASK(const MUTANT_ACCESS_MASK&) = default;
    MUTANT_ACCESS_MASK& operator=(const MUTANT_ACCESS_MASK&) = default;
};

const std::string& to_string(MutantAccessMaskFlag);
std::ostream& operator<<(std::ostream&, MutantAccessMaskFlag);

std::string to_string(MUTANT_ACCESS_MASK);
std::ostream& operator<<(std::ostream&, MUTANT_ACCESS_MASK);

} /* namespace nt */
} /* namespace windows */
} /* namespace introvirt */
