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
 * @brief Valid flags for EVENT_ACCESS_MASK
 *
 * @see EVENT_ACCESS_MASK
 */
enum EventAccessMaskFlag {
    /// Read state information
    EVENT_QUERY_STATE = 0x1,
    /// Modify state access, which is required for the SetEvent, ResetEvent and PulseEvent
    /// functions.
    EVENT_MODIFY_STATE = 0x2,
    /// Full access to the state
    EVENT_ALL_ACCESS = 0x1F0000 | EVENT_QUERY_STATE | EVENT_MODIFY_STATE,
};

/**
 * @brief ACCESS_MASK class for event permissions
 *
 * @see EventAccessMaskFlag
 */
class EVENT_ACCESS_MASK final : public ACCESS_MASK {
  public:
    /**
     * @brief Check if the given flag is enabled
     *
     * @param flag
     * @return true
     * @return false
     */
    bool has(EventAccessMaskFlag flag) const { return (value() & flag) == flag; }

    /**
     * @brief Set the state of the given flag to enabled
     *
     * @param flag The flag to enable
     */
    void set(EventAccessMaskFlag flag) { value(value() | flag); }

    /**
     * @brief Clear the given flag
     *
     * @param flag The flag to clear
     */
    void clear(EventAccessMaskFlag flag) { value(value() & ~flag); }

    AccessMaskType type() const override { return EventAccessMask; }

    // Constructors and assignment operators
    EVENT_ACCESS_MASK() = default;
    EVENT_ACCESS_MASK(uint32_t mask) : ACCESS_MASK(mask) {}

    EVENT_ACCESS_MASK(const EVENT_ACCESS_MASK&) = default;
    EVENT_ACCESS_MASK& operator=(const EVENT_ACCESS_MASK&) = default;
};

const std::string& to_string(EventAccessMaskFlag);
std::ostream& operator<<(std::ostream&, EventAccessMaskFlag);

std::string to_string(EVENT_ACCESS_MASK);
std::ostream& operator<<(std::ostream&, EVENT_ACCESS_MASK);

} /* namespace nt */
} /* namespace windows */
} /* namespace introvirt */
