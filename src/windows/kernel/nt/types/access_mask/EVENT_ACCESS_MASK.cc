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
#include <introvirt/windows/kernel/nt/types/access_mask/EVENT_ACCESS_MASK.hh>
#include <sstream>

namespace introvirt {
namespace windows {
namespace nt {

const std::string& to_string(EventAccessMaskFlag flag) {
    static const std::string EVENT_QUERY_STATE_STR("EVENT_QUERY_STATE");
    static const std::string EVENT_MODIFY_STATE_STR("EVENT_MODIFY_STATE");
    static const std::string EVENT_ALL_ACCESS_STR("EVENT_ALL_ACCESS");
    const static std::string UNKNOWN_STR("UNKNOWN");

    switch (flag) {
    case EventAccessMaskFlag::EVENT_QUERY_STATE:
        return EVENT_QUERY_STATE_STR;
    case EventAccessMaskFlag::EVENT_MODIFY_STATE:
        return EVENT_MODIFY_STATE_STR;
    case EventAccessMaskFlag::EVENT_ALL_ACCESS:
        return EVENT_ALL_ACCESS_STR;
    }

    return UNKNOWN_STR;
}

std::ostream& operator<<(std::ostream& os, EventAccessMaskFlag flag) {
    os << to_string(flag);
    return os;
}

std::string to_string(EVENT_ACCESS_MASK mask) {
    std::ostringstream ss;
    ss << mask;
    return ss.str();
}

#define WRITE_IF_ENABLED(flag)                                                                     \
    if (mask.has(flag)) {                                                                          \
        os << to_string(flag) << ' ';                                                              \
        mask.clear(flag);                                                                          \
    }

std::ostream& operator<<(std::ostream& os, EVENT_ACCESS_MASK mask) {
    WRITE_IF_ENABLED(EventAccessMaskFlag::EVENT_ALL_ACCESS);

    WRITE_IF_ENABLED(EventAccessMaskFlag::EVENT_QUERY_STATE);
    WRITE_IF_ENABLED(EventAccessMaskFlag::EVENT_MODIFY_STATE);

    // Now call the base class to handle any remaining bits
    ACCESS_MASK base(mask.value());
    os << base;

    return os;
}

} /* namespace nt */
} /* namespace windows */
} /* namespace introvirt */
