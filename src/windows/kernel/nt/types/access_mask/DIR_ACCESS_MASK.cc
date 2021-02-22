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
#include <introvirt/windows/kernel/nt/types/access_mask/DIR_ACCESS_MASK.hh>
#include <sstream>

namespace introvirt {
namespace windows {
namespace nt {

const std::string& to_string(DirAccessMaskFlag flag) {
    const static std::string DIRECTORY_QUERY_STR("DIRECTORY_QUERY");
    const static std::string DIRECTORY_TRAVERSE_STR("DIRECTORY_TRAVERSE");
    const static std::string DIRECTORY_CREATE_OBJECT_STR("DIRECTORY_CREATE_OBJECT");
    const static std::string DIRECTORY_CREATE_SUBDIRECTORY_STR("DIRECTORY_CREATE_SUBDIRECTORY");
    const static std::string DIRECTORY_ALL_ACCESS_STR("DIRECTORY_ALL_ACCESS");
    const static std::string UNKNOWN_STR("UNKNOWN");

    switch (flag) {
    case DirAccessMaskFlag::DIRECTORY_QUERY:
        return DIRECTORY_QUERY_STR;
    case DirAccessMaskFlag::DIRECTORY_TRAVERSE:
        return DIRECTORY_TRAVERSE_STR;
    case DirAccessMaskFlag::DIRECTORY_CREATE_OBJECT:
        return DIRECTORY_CREATE_OBJECT_STR;
    case DirAccessMaskFlag::DIRECTORY_CREATE_SUBDIRECTORY:
        return DIRECTORY_CREATE_SUBDIRECTORY_STR;
    case DirAccessMaskFlag::DIRECTORY_ALL_ACCESS:
        return DIRECTORY_ALL_ACCESS_STR;
    }

    return UNKNOWN_STR;
}

std::ostream& operator<<(std::ostream& os, DirAccessMaskFlag flag) {
    os << to_string(flag);
    return os;
}

std::string to_string(DIR_ACCESS_MASK mask) {
    std::ostringstream ss;
    ss << mask;
    return ss.str();
}

#define WRITE_IF_ENABLED(flag)                                                                     \
    if (mask.has(flag)) {                                                                          \
        os << to_string(flag) << ' ';                                                              \
        mask.clear(flag);                                                                          \
    }

std::ostream& operator<<(std::ostream& os, DIR_ACCESS_MASK mask) {
    WRITE_IF_ENABLED(DirAccessMaskFlag::DIRECTORY_ALL_ACCESS);

    WRITE_IF_ENABLED(DirAccessMaskFlag::DIRECTORY_QUERY);
    WRITE_IF_ENABLED(DirAccessMaskFlag::DIRECTORY_TRAVERSE);
    WRITE_IF_ENABLED(DirAccessMaskFlag::DIRECTORY_CREATE_OBJECT);
    WRITE_IF_ENABLED(DirAccessMaskFlag::DIRECTORY_CREATE_SUBDIRECTORY);

    // Now call the base class to handle any remaining bits
    ACCESS_MASK base(mask.value());
    os << base;

    return os;
}

} /* namespace nt */
} /* namespace windows */
} /* namespace introvirt */
