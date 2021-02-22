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

enum ThreadCreateFlag {
    CREATE_SUSPENDED = 0x00000001,
    SKIP_THREAD_ATTACH = 0x00000002,
    HIDE_FROM_DEBUGGER = 0x00000004,
    HAS_SECURITY_DESCRIPTOR = 0x00000010,
    ACCESS_CHECK_IN_TARGET = 0x00000020,
    INITIAL_THREAD = 0x00000080,
};

class ThreadCreateFlags {
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
    bool has(ThreadCreateFlag flag) const { return (value_ & flag) != 0u; }

    /**
     * @param flag The flag to disable
     */
    void clear(ThreadCreateFlag flag) { value_ &= ~(static_cast<uint32_t>(flag)); }

    /**
     * @param flag The flag to enable
     */
    void set(ThreadCreateFlag flag) { value_ |= flag; }

    /**
     * @param separator The separator to use between flags
     * @returns A human readable string
     */
    std::string to_string(const std::string& separator = " ") const;

    ThreadCreateFlags() : value_(0) {}
    ThreadCreateFlags(uint32_t value) : value_(value) {}

  private:
    uint32_t value_ = 0;
};

std::string to_string(const ThreadCreateFlags& flags, const std::string& separator = " ");
std::ostream& operator<<(std::ostream& os, const ThreadCreateFlags& flags);

} /* namespace nt */
} /* namespace windows */
} /* namespace introvirt */
