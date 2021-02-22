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

#include "ACCESS_MASK.hh"

namespace introvirt {
namespace windows {
namespace nt {

/**
 * @brief Valid flags for FILE_ACCESS_MASK
 *
 * <a href="https://docs.microsoft.com/en-us/windows/win32/fileio/file-access-rights-constants">MSDN
 * Article</a>
 *
 * @see FILE_ACCESS_MASK
 *
 */
enum FileAccessMaskFlag {
    /// For a file object, the right to read the corresponding file data. For a directory object,
    /// the right to read the corresponding directory data.
    FILE_READ_DATA = 0x001,

    /// For a file object, the right to write data to the file.
    FILE_WRITE_DATA = 0x002,

    /// For a file object, the right to append data to the file.
    FILE_APPEND_DATA = 0x004,

    /// For a native code file, the right to execute the file. This access right given to scripts
    /// may cause the script to be executable, depending on the script interpreter.
    FILE_EXECUTE = 0x020,

    /// The right to read extended file attributes.
    FILE_READ_EA = 0x008,

    /// The right to write extended file attributes.
    FILE_WRITE_EA = 0x010,

    /// The right to read file attributes.
    FILE_READ_ATTRIBUTES = 0x080,

    /// The right to write file attributes.
    FILE_WRITE_ATTRIBUTES = 0x100,

    /// For a directory, the right to list the contents of the directory.
    FILE_LIST_DIRECTORY = 0x001,

    /// For a directory, the right to create a file in the directory.
    FILE_ADD_FILE = 0x002,

    /// For a directory, the right to create a subdirectory.
    FILE_ADD_SUBDIRECTORY = 0x004,

    /// For a directory, the right to traverse the directory.
    FILE_TRAVERSE = 0x020,

    /// For a directory, the right to delete a directory and all the files it contains, including
    /// read-only files.
    FILE_DELETE_CHILD = 0x040,

    /// For a named pipe, the right to create a pipe.
    FILE_CREATE_PIPE_INSTANCE = 0x004,

    /// All possible access rights for a file.
    FILE_ALL_ACCESS = STANDARD_RIGHTS_REQUIRED | SYNCHRONIZE | 0x1FF,

    /// Generic execute bits for a file
    FILE_GENERIC_EXECUTE = FILE_EXECUTE | FILE_READ_ATTRIBUTES | READ_CONTROL | SYNCHRONIZE,

    /// Generic read bits for a file
    FILE_GENERIC_READ =
        FILE_READ_ATTRIBUTES | FILE_READ_DATA | FILE_READ_EA | READ_CONTROL | SYNCHRONIZE,

    // Generic write bits for a file
    FILE_GENERIC_WRITE = FILE_APPEND_DATA | FILE_WRITE_ATTRIBUTES | FILE_WRITE_DATA |
                         FILE_WRITE_EA | READ_CONTROL | SYNCHRONIZE,
};

/**
 * @brief ACCESS_MASK class for file permissions
 *
 * @see FileAccessMaskFlags
 */
class FILE_ACCESS_MASK final : public ACCESS_MASK {
  public:
    /**
     * @brief Check if the given flag is enabled
     *
     * @param flag
     * @return true
     * @return false
     */
    bool has(FileAccessMaskFlag flag) const { return (value() & flag) == flag; }

    /**
     * @brief Set the state of the given flag to enabled
     *
     * @param flag The flag to enable
     */
    void set(FileAccessMaskFlag flag) { value(value() | flag); }

    /**
     * @brief Clear the given flag
     *
     * @param flag The flag to clear
     */
    void clear(FileAccessMaskFlag flag) { value(value() & ~flag); }

    AccessMaskType type() const override { return FileAccessMask; }

    // Constructors and assignment operators
    FILE_ACCESS_MASK() = default;
    FILE_ACCESS_MASK(uint32_t mask) : ACCESS_MASK(mask) {}

    FILE_ACCESS_MASK(const FILE_ACCESS_MASK&) = default;
    FILE_ACCESS_MASK& operator=(const FILE_ACCESS_MASK&) = default;
};

const std::string& to_string(FileAccessMaskFlag);
std::ostream& operator<<(std::ostream&, FileAccessMaskFlag);

std::string to_string(FILE_ACCESS_MASK);
std::ostream& operator<<(std::ostream&, FILE_ACCESS_MASK);

} /* namespace nt */
} /* namespace windows */
} /* namespace introvirt */
