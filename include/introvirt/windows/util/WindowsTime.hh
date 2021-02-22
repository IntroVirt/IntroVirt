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
#include <memory>
#include <string>

namespace introvirt {
namespace windows {

/**
 * @brief Helper class for the Windows time format
 *
 * Windows uses times based on nanoseconds since January 1, 1601.
 * This class provides conversion to and from UNIX time.
 *
 * Note that times will be in UTC
 */
class WindowsTime final {
  public:
    /**
     * Create a WindowsTime object directly from Windows format
     *
     * @param winTime The Windows time value
     * @returns A WindowsTime object
     */
    static WindowsTime from_windows_time(uint64_t winTime);

    /**
     * Create a WindowsTime object from UNIX format
     *
     * @param unixTime The UNIX time value
     * @returns A WindowsTime object
     */
    static WindowsTime from_unix_time(uint64_t unixTime);

  public:
    /**
     * @returns The time value in Windows time
     */
    uint64_t windows_time() const;
    operator uint64_t() const;

    /**
     * @returns The time value in UNIX time
     */
    uint64_t unix_time() const;

    /**
     * @returns A human readable time string
     */
    std::string string() const;

    /**
     * @brief Copy constructor
     */
    WindowsTime(const WindowsTime& other);

    /**
     * @brief Copy assignment operator
     */
    WindowsTime& operator=(const WindowsTime& other);

    /**
     * @brief Move constructor
     */
    WindowsTime(WindowsTime&& other) noexcept;

    /**
     * @brief Move assignment operator
     */
    WindowsTime& operator=(WindowsTime&& other) noexcept;

    ~WindowsTime() = default;

  private:
    /**
     * Private constructor
     */
    WindowsTime();

  private:
    uint64_t windows_time_;
};

std::string to_string(const WindowsTime& time);

std::ostream& operator<<(std::ostream& os, const WindowsTime& time);

} /* namespace windows */
} /* namespace introvirt */
