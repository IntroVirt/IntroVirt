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
#include <introvirt/windows/kernel/nt/types/access_mask/SECTION_ACCESS_MASK.hh>
#include <sstream>

namespace introvirt {
namespace windows {
namespace nt {

const std::string& to_string(SectionAccessMaskFlag flag) {
    static const std::string SECTION_QUERY_STR("SECTION_QUERY");
    static const std::string SECTION_MAP_WRITE_STR("SECTION_MAP_WRITE");
    static const std::string SECTION_MAP_READ_STR("SECTION_MAP_READ");
    static const std::string SECTION_MAP_EXECUTE_STR("SECTION_MAP_EXECUTE");
    static const std::string SECTION_EXTEND_SIZE_STR("SECTION_EXTEND_SIZE");
    static const std::string SECTION_MAP_EXECUTE_EXPLICIT_STR("SECTION_MAP_EXECUTE_EXPLICIT");
    static const std::string UNKNOWN_STR("UNKNOWN");

    switch (flag) {
    case SectionAccessMaskFlag::SECTION_QUERY:
        return SECTION_QUERY_STR;
    case SectionAccessMaskFlag::SECTION_MAP_WRITE:
        return SECTION_MAP_WRITE_STR;
    case SectionAccessMaskFlag::SECTION_MAP_READ:
        return SECTION_MAP_READ_STR;
    case SectionAccessMaskFlag::SECTION_MAP_EXECUTE:
        return SECTION_MAP_EXECUTE_STR;
    case SectionAccessMaskFlag::SECTION_EXTEND_SIZE:
        return SECTION_EXTEND_SIZE_STR;
    case SectionAccessMaskFlag::SECTION_MAP_EXECUTE_EXPLICIT:
        return SECTION_MAP_EXECUTE_EXPLICIT_STR;
    }

    return UNKNOWN_STR;
}

std::ostream& operator<<(std::ostream& os, SectionAccessMaskFlag flag) {
    os << to_string(flag);
    return os;
}

std::string to_string(SECTION_ACCESS_MASK mask) {
    std::ostringstream ss;
    ss << mask;
    return ss.str();
}

#define WRITE_IF_ENABLED(flag)                                                                     \
    if (mask.has(flag)) {                                                                          \
        os << to_string(flag) << ' ';                                                              \
        mask.clear(flag);                                                                          \
    }

std::ostream& operator<<(std::ostream& os, SECTION_ACCESS_MASK mask) {
    WRITE_IF_ENABLED(SectionAccessMaskFlag::SECTION_ALL_ACCESS);

    WRITE_IF_ENABLED(SectionAccessMaskFlag::SECTION_QUERY);
    WRITE_IF_ENABLED(SectionAccessMaskFlag::SECTION_MAP_WRITE);
    WRITE_IF_ENABLED(SectionAccessMaskFlag::SECTION_MAP_READ);
    WRITE_IF_ENABLED(SectionAccessMaskFlag::SECTION_MAP_EXECUTE);
    WRITE_IF_ENABLED(SectionAccessMaskFlag::SECTION_EXTEND_SIZE);
    WRITE_IF_ENABLED(SectionAccessMaskFlag::SECTION_MAP_EXECUTE_EXPLICIT);

    // Now call the base class to handle any remaining bits
    ACCESS_MASK base(mask.value());
    os << base;

    return os;
}

} /* namespace nt */
} /* namespace windows */
} /* namespace introvirt */
