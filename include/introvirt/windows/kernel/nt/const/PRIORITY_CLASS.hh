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

#include <ostream>
#include <string>

namespace introvirt {
namespace windows {
namespace nt {

enum PRIORITY_CLASS {
    IDLE_PRIORITY_CLASS = 0x00000040,
    NORMAL_PRIORITY_CLASS = 0x00000020,
    HIGH_PRIORITY_CLASS = 0x00000080,
    REALTIME_PRIORITY_CLASS = 0x00000100,
    BELOW_NORMAL_PRIORITY_CLASS = 0x00004000,
    ABOVE_NORMAL_PRIORITY_CLASS = 0x00008000,

    // IntroVirt value for handling invalid values
    UNKNOWN_PRIORITY_CLASS = 0xFFFFFFFF
};

const std::string& to_string(PRIORITY_CLASS value);
std::ostream& operator<<(std::ostream& os, PRIORITY_CLASS value);

} // namespace nt
} // namespace windows
} // namespace introvirt