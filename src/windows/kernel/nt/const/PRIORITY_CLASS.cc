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
#include <introvirt/windows/kernel/nt/const/PRIORITY_CLASS.hh>

namespace introvirt {
namespace windows {
namespace nt {

static const std::string ABOVE_NORMAL_PRIORITY_CLASS_STR("ABOVE_NORMAL_PRIORITY_CLASS");
static const std::string BELOW_NORMAL_PRIORITY_CLASS_STR("BELOW_NORMAL_PRIORITY_CLASS");
static const std::string HIGH_PRIORITY_CLASS_STR("HIGH_PRIORITY_CLASS");
static const std::string IDLE_PRIORITY_CLASS_STR("IDLE_PRIORITY_CLASS");
static const std::string NORMAL_PRIORITY_CLASS_STR("NORMAL_PRIORITY_CLASS");
static const std::string REALTIME_PRIORITY_CLASS_STR("REALTIME_PRIORITY_CLASS");
static const std::string UNKNOWN_STR("Unknown");

const std::string& to_string(PRIORITY_CLASS value) {
    switch (value) {
    case PRIORITY_CLASS::BELOW_NORMAL_PRIORITY_CLASS:
        return BELOW_NORMAL_PRIORITY_CLASS_STR;
    case PRIORITY_CLASS::NORMAL_PRIORITY_CLASS:
        return NORMAL_PRIORITY_CLASS_STR;
    case PRIORITY_CLASS::ABOVE_NORMAL_PRIORITY_CLASS:
        return ABOVE_NORMAL_PRIORITY_CLASS_STR;
    case PRIORITY_CLASS::HIGH_PRIORITY_CLASS:
        return HIGH_PRIORITY_CLASS_STR;
    case PRIORITY_CLASS::REALTIME_PRIORITY_CLASS:
        return REALTIME_PRIORITY_CLASS_STR;
    case PRIORITY_CLASS::IDLE_PRIORITY_CLASS:
        return IDLE_PRIORITY_CLASS_STR;
    case PRIORITY_CLASS::UNKNOWN_PRIORITY_CLASS:
        return UNKNOWN_STR;
    }

    return UNKNOWN_STR;
}

std::ostream& operator<<(std::ostream& os, PRIORITY_CLASS value) {
    os << to_string(value);
    return os;
}

} // namespace nt
} // namespace windows
} // namespace introvirt