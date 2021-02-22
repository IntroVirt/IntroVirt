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

#include <introvirt/util/json/json.hh>

#include <cstdint>
#include <sstream>
#include <string>

namespace introvirt {
namespace windows {
namespace nt {

enum FILE_ATTRIBUTE_TYPE {
    FILE_ATTRIBUTE_READONLY = 0x00000001,
    FILE_ATTRIBUTE_HIDDEN = 0x00000002,
    FILE_ATTRIBUTE_SYSTEM = 0x00000004,
    FILE_ATTRIBUTE_DIRECTORY = 0x00000010,
    FILE_ATTRIBUTE_ARCHIVE = 0x00000020,
    FILE_ATTRIBUTE_DEVICE = 0x00000040,
    FILE_ATTRIBUTE_NORMAL = 0x00000080,
    FILE_ATTRIBUTE_TEMPORARY = 0x00000100,
    FILE_ATTRIBUTE_SPARSE_FILE = 0x00000200,
    FILE_ATTRIBUTE_REPARSE_POINT = 0x00000400,
    FILE_ATTRIBUTE_COMPRESSED = 0x00000800,
    FILE_ATTRIBUTE_OFFLINE = 0x00001000,
    FILE_ATTRIBUTE_NOT_CONTENT_INDEXED = 0x00002000,
    FILE_ATTRIBUTE_ENCRYPTED = 0x00004000,
    FILE_ATTRIBUTE_VIRTUAL = 0x00010000
};

class FILE_ATTRIBUTES {
  public:
    FILE_ATTRIBUTES(uint32_t attributes) : attributes(attributes) {}

  public:
    inline bool isReadOnly() const;
    inline bool isHidden() const;
    inline bool isSystem() const;
    inline bool isDirectory() const;
    inline bool isArchive() const;
    inline bool isDevice() const;
    inline bool isNormal() const;
    inline bool isTemporary() const;
    inline bool isSparseFile() const;
    inline bool isReparsePoint() const;
    inline bool isCompressed() const;
    inline bool isOffline() const;
    inline bool isNotContentIndexed() const;
    inline bool isEncrypted() const;
    inline bool isVirtual() const;

    inline operator uint32_t() const;
    inline uint32_t get() const;

    inline operator Json::Value() const;
    Json::Value json() const;

    /**
     * @brief Get the attributes as a directory listing string
     *
     * @return std::string
     */
    std::string dir_string() const;

  private:
    uint32_t attributes;
};

inline bool FILE_ATTRIBUTES::isReadOnly() const {
    return (attributes & FILE_ATTRIBUTE_READONLY) != 0u;
}
inline bool FILE_ATTRIBUTES::isHidden() const { return (attributes & FILE_ATTRIBUTE_HIDDEN) != 0u; }
inline bool FILE_ATTRIBUTES::isSystem() const { return (attributes & FILE_ATTRIBUTE_SYSTEM) != 0u; }
inline bool FILE_ATTRIBUTES::isDirectory() const {
    return (attributes & FILE_ATTRIBUTE_DIRECTORY) != 0u;
}
inline bool FILE_ATTRIBUTES::isArchive() const {
    return (attributes & FILE_ATTRIBUTE_ARCHIVE) != 0u;
}
inline bool FILE_ATTRIBUTES::isDevice() const { return (attributes & FILE_ATTRIBUTE_DEVICE) != 0u; }
inline bool FILE_ATTRIBUTES::isNormal() const { return (attributes & FILE_ATTRIBUTE_NORMAL) != 0u; }
inline bool FILE_ATTRIBUTES::isTemporary() const {
    return (attributes & FILE_ATTRIBUTE_TEMPORARY) != 0u;
}
inline bool FILE_ATTRIBUTES::isSparseFile() const {
    return (attributes & FILE_ATTRIBUTE_SPARSE_FILE) != 0u;
}
inline bool FILE_ATTRIBUTES::isReparsePoint() const {
    return (attributes & FILE_ATTRIBUTE_REPARSE_POINT) != 0u;
}
inline bool FILE_ATTRIBUTES::isCompressed() const {
    return (attributes & FILE_ATTRIBUTE_COMPRESSED) != 0u;
}
inline bool FILE_ATTRIBUTES::isOffline() const {
    return (attributes & FILE_ATTRIBUTE_OFFLINE) != 0u;
}
inline bool FILE_ATTRIBUTES::isNotContentIndexed() const {
    return (attributes & FILE_ATTRIBUTE_NOT_CONTENT_INDEXED) != 0u;
}
inline bool FILE_ATTRIBUTES::isEncrypted() const {
    return (attributes & FILE_ATTRIBUTE_ENCRYPTED) != 0u;
}
inline bool FILE_ATTRIBUTES::isVirtual() const {
    return (attributes & FILE_ATTRIBUTE_VIRTUAL) != 0u;
}

inline FILE_ATTRIBUTES::operator uint32_t() const { return attributes; }

inline uint32_t FILE_ATTRIBUTES::get() const { return attributes; }

inline FILE_ATTRIBUTES::operator Json::Value() const { return json(); }

const std::string& to_string(FILE_ATTRIBUTE_TYPE);
std::string to_string(FILE_ATTRIBUTES);

} /* namespace nt */
} /* namespace windows */
} /* namespace introvirt */
