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

#include <introvirt/windows/util/WindowsTime.hh>

#include <ctime>

namespace introvirt {
namespace windows {

WindowsTime WindowsTime::from_windows_time(uint64_t winTime) {
    WindowsTime time;
    time.windows_time_ = winTime;
    return time;
}

WindowsTime WindowsTime::from_unix_time(uint64_t unixTime) {
    WindowsTime time;
    time.windows_time_ = (unixTime + 11644473600) * 10000000;
    return time;
}

uint64_t WindowsTime::unix_time() const { return (windows_time_ / 10000000) - 11644473600; }
uint64_t WindowsTime::windows_time() const { return windows_time_; }

WindowsTime::operator uint64_t() const { return windows_time(); }

std::string WindowsTime::string() const {
    time_t rawTime = unix_time();

    struct tm* timeinfo = localtime(&rawTime);

    std::string result = asctime(timeinfo);
    return result.substr(0, result.length() - 1);
}

WindowsTime::WindowsTime() = default;
WindowsTime::WindowsTime(const WindowsTime& other) = default;
WindowsTime& WindowsTime::operator=(const WindowsTime& other) = default;
WindowsTime::WindowsTime(WindowsTime&& other) noexcept = default;
WindowsTime& WindowsTime::operator=(WindowsTime&& other) noexcept = default;

std::ostream& operator<<(std::ostream& os, const WindowsTime& time) {
    os << time.string();
    return os;
}

std::string to_string(const WindowsTime& time) { return time.string(); }

} /* namespace windows */
} /* namespace introvirt */
