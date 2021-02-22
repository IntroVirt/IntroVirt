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
#include <introvirt/windows/kernel/nt/types/access_mask/FILE_ACCESS_MASK.hh>
#include <sstream>

namespace introvirt {
namespace windows {
namespace nt {

const std::string& to_string(FileAccessMaskFlag flag) {
    static const std::string FILE_READ_DATA_STR("FILE_READ_DATA");
    static const std::string FILE_WRITE_DATA_STR("FILE_WRITE_DATA");
    static const std::string FILE_APPEND_DATA_STR("FILE_APPEND_DATA");
    static const std::string FILE_READ_EA_STR("FILE_READ_EA");
    static const std::string FILE_WRITE_EA_STR("FILE_WRITE_EA");
    static const std::string FILE_EXECUTE_STR("FILE_EXECUTE");
    static const std::string FILE_DELETE_CHILD_STR("FILE_DELETE_CHILD");
    static const std::string FILE_READ_ATTRIBUTES_STR("FILE_READ_ATTRIBUTES");
    static const std::string FILE_WRITE_ATTRIBUTES_STR("FILE_WRITE_ATTRIBUTES");
    static const std::string FILE_GENERIC_EXECUTE_STR("FILE_GENERIC_EXECUTE");
    static const std::string FILE_GENERIC_READ_STR("FILE_GENERIC_READ");
    static const std::string FILE_GENERIC_WRITE_STR("FILE_GENERIC_WRITE");
    static const std::string FILE_ALL_ACCESS_STR("FILE_ALL_ACCESS");
    static const std::string UNKNOWN_STR("UNKNOWN");

    switch (flag) {
    case FileAccessMaskFlag::FILE_READ_DATA:
        return FILE_READ_DATA_STR;
    case FileAccessMaskFlag::FILE_WRITE_DATA:
        return FILE_WRITE_DATA_STR;
    case FileAccessMaskFlag::FILE_APPEND_DATA:
        return FILE_APPEND_DATA_STR;
    case FileAccessMaskFlag::FILE_READ_EA:
        return FILE_READ_EA_STR;
    case FileAccessMaskFlag::FILE_WRITE_EA:
        return FILE_WRITE_EA_STR;
    case FileAccessMaskFlag::FILE_EXECUTE:
        return FILE_EXECUTE_STR;
    case FileAccessMaskFlag::FILE_DELETE_CHILD:
        return FILE_DELETE_CHILD_STR;
    case FileAccessMaskFlag::FILE_READ_ATTRIBUTES:
        return FILE_READ_ATTRIBUTES_STR;
    case FileAccessMaskFlag::FILE_WRITE_ATTRIBUTES:
        return FILE_WRITE_ATTRIBUTES_STR;
    case FileAccessMaskFlag::FILE_GENERIC_EXECUTE:
        return FILE_GENERIC_EXECUTE_STR;
    case FileAccessMaskFlag::FILE_GENERIC_READ:
        return FILE_GENERIC_READ_STR;
    case FileAccessMaskFlag::FILE_GENERIC_WRITE:
        return FILE_GENERIC_WRITE_STR;
    case FileAccessMaskFlag::FILE_ALL_ACCESS:
        return FILE_ALL_ACCESS_STR;
    }

    return UNKNOWN_STR;
}

std::ostream& operator<<(std::ostream& os, FileAccessMaskFlag flag) {
    os << to_string(flag);
    return os;
}

std::string to_string(FILE_ACCESS_MASK mask) {
    std::ostringstream ss;
    ss << mask;
    return ss.str();
}

#define WRITE_IF_ENABLED(flag)                                                                     \
    if (mask.has(flag)) {                                                                          \
        os << to_string(flag) << ' ';                                                              \
        mask.clear(flag);                                                                          \
    }

std::ostream& operator<<(std::ostream& os, FILE_ACCESS_MASK mask) {
    WRITE_IF_ENABLED(FileAccessMaskFlag::FILE_ALL_ACCESS);

    WRITE_IF_ENABLED(FileAccessMaskFlag::FILE_GENERIC_EXECUTE);
    WRITE_IF_ENABLED(FileAccessMaskFlag::FILE_GENERIC_READ);
    WRITE_IF_ENABLED(FileAccessMaskFlag::FILE_GENERIC_WRITE);

    WRITE_IF_ENABLED(FileAccessMaskFlag::FILE_READ_DATA);
    WRITE_IF_ENABLED(FileAccessMaskFlag::FILE_WRITE_DATA);
    WRITE_IF_ENABLED(FileAccessMaskFlag::FILE_APPEND_DATA);
    WRITE_IF_ENABLED(FileAccessMaskFlag::FILE_READ_EA);
    WRITE_IF_ENABLED(FileAccessMaskFlag::FILE_WRITE_EA);
    WRITE_IF_ENABLED(FileAccessMaskFlag::FILE_EXECUTE);
    WRITE_IF_ENABLED(FileAccessMaskFlag::FILE_DELETE_CHILD);
    WRITE_IF_ENABLED(FileAccessMaskFlag::FILE_READ_ATTRIBUTES);
    WRITE_IF_ENABLED(FileAccessMaskFlag::FILE_WRITE_ATTRIBUTES);

    // Now call the base class to handle any remaining bits
    ACCESS_MASK base(mask.value());
    os << base;

    return os;
}

} /* namespace nt */
} /* namespace windows */
} /* namespace introvirt */
