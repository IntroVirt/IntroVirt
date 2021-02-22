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

#include <cstdint>
#include <string>

namespace introvirt {
namespace windows {
namespace nt {

enum ProcessCreateFlag {
    BREAKAWAY = 0x00000001,
    NO_DEBUG_INHERIT = 0x00000002,
    INHERIT_HANDLES = 0x00000004,
    OVERRIDE_ADDRESS_SPACE = 0x00000008,
    LARGE_PAGES = 0x00000010,
};

class ProcessCreateFlags {
  public:
    /**
     * @returns The raw value
     */
    uint32_t value() const { return value_; }

    operator uint32_t() const { return value_; }

    /**
     * @param value The raw value to set
     */
    void value(uint32_t value) { value_ = value; }

    /**
     * @param flag The flag to check
     * @returns True if the given flag is enabled
     */
    bool has(ProcessCreateFlag flag) const { return (value_ & flag) != 0u; }

    /**
     * @param flag The flag to disable
     */
    void clear(ProcessCreateFlag flag) { value_ &= ~(static_cast<uint32_t>(flag)); }

    /**
     * @param flag The flag to enable
     */
    void set(ProcessCreateFlag flag) { value_ |= flag; }

    /**
     * @param separator The separator to use between flags
     * @returns A human readable string
     */
    std::string to_string(const std::string& separator = " ") const;

    ProcessCreateFlags() : value_(0) {}
    ProcessCreateFlags(uint32_t value) : value_(value) {}

  private:
    uint32_t value_;
};

std::string to_string(ProcessCreateFlags options, const std::string& separator = " ");
std::ostream& operator<<(std::ostream& os, ProcessCreateFlags);

} /* namespace nt */
} /* namespace windows */
} /* namespace introvirt */
