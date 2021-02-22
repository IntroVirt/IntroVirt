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

#include <introvirt/windows/kernel/nt/const/FileCreateOptions.hh>
#include <sstream>

namespace introvirt {
namespace windows {
namespace nt {

FileCreateOptions::FileCreateOptions() = default;

FileCreateOptions::FileCreateOptions(uint32_t value) : value(value) {}

uint32_t FileCreateOptions::get() const { return value; }
FileCreateOptions::operator uint32_t() const { return value; }
void FileCreateOptions::set(uint32_t value) { this->value = value; }
bool FileCreateOptions::isFlagEnabled(FileCreateOptionsFlags flag) const {
    return (value & flag) != 0u;
}
void FileCreateOptions::disableFlag(FileCreateOptionsFlags flag) {
    value &= ~(static_cast<uint32_t>(flag));
}
void FileCreateOptions::enableFlag(FileCreateOptionsFlags flag) { value |= flag; }

std::string FileCreateOptions::to_string(const std::string& separator) const {
    std::ostringstream result;

    if ((value & FileCreateOptionsFlags::FILE_DIRECTORY_FILE) != 0u) {
        result << "FILE_DIRECTORY_FILE" << separator;
    }
    if ((value & FileCreateOptionsFlags::FILE_WRITE_THROUGH) != 0u) {
        result << "FILE_WRITE_THROUGH" << separator;
    }
    if ((value & FileCreateOptionsFlags::FILE_SEQUENTIAL_ONLY) != 0u) {
        result << "FILE_SEQUENTIAL_ONLY" << separator;
    }
    if ((value & FileCreateOptionsFlags::FILE_NO_INTERMEDIATE_BUFFERING) != 0u) {
        result << "FILE_NO_INTERMEDIATE_BUFFERING" << separator;
    }
    if ((value & FileCreateOptionsFlags::FILE_SYNCHRONOUS_IO_ALERT) != 0u) {
        result << "FILE_SYNCHRONOUS_IO_ALERT" << separator;
    }
    if ((value & FileCreateOptionsFlags::FILE_SYNCHRONOUS_IO_NONALERT) != 0u) {
        result << "FILE_SYNCHRONOUS_IO_NONALERT" << separator;
    }
    if ((value & FileCreateOptionsFlags::FILE_NON_DIRECTORY_FILE) != 0u) {
        result << "FILE_NON_DIRECTORY_FILE" << separator;
    }
    if ((value & FileCreateOptionsFlags::FILE_CREATE_TREE_CONNECTION) != 0u) {
        result << "FILE_CREATE_TREE_CONNECTION" << separator;
    }
    if ((value & FileCreateOptionsFlags::FILE_COMPLETE_IF_OPLOCKED) != 0u) {
        result << "FILE_COMPLETE_IF_OPLOCKED" << separator;
    }
    if ((value & FileCreateOptionsFlags::FILE_NO_EA_KNOWLEDGE) != 0u) {
        result << "FILE_NO_EA_KNOWLEDGE" << separator;
    }
    if ((value & FileCreateOptionsFlags::FILE_OPEN_FOR_RECOVERY) != 0u) {
        result << "FILE_OPEN_FOR_RECOVERY" << separator;
    }
    if ((value & FileCreateOptionsFlags::FILE_RANDOM_ACCESS) != 0u) {
        result << "FILE_RANDOM_ACCESS" << separator;
    }
    if ((value & FileCreateOptionsFlags::FILE_DELETE_ON_CLOSE) != 0u) {
        result << "FILE_DELETE_ON_CLOSE" << separator;
    }
    if ((value & FileCreateOptionsFlags::FILE_OPEN_BY_FILE_ID) != 0u) {
        result << "FILE_OPEN_BY_FILE_ID" << separator;
    }
    if ((value & FileCreateOptionsFlags::FILE_OPEN_FOR_BACKUP_INTENT) != 0u) {
        result << "FILE_OPEN_FOR_BACKUP_INTENT" << separator;
    }
    if ((value & FileCreateOptionsFlags::FILE_NO_COMPRESSION) != 0u) {
        result << "FILE_NO_COMPRESSION" << separator;
    }
    if ((value & FileCreateOptionsFlags::FILE_OPEN_REQUIRING_OPLOCK) != 0u) {
        result << "FILE_OPEN_REQUIRING_OPLOCK" << separator;
    }
    if ((value & FileCreateOptionsFlags::FILE_DISALLOW_EXCLUSIVE) != 0u) {
        result << "FILE_DISALLOW_EXCLUSIVE" << separator;
    }
    if ((value & FileCreateOptionsFlags::FILE_SESSION_AWARE) != 0u) {
        result << "FILE_SESSION_AWARE" << separator;
    }
    if ((value & FileCreateOptionsFlags::FILE_RESERVE_OPFILTER) != 0u) {
        result << "FILE_RESERVE_OPFILTER" << separator;
    }
    if ((value & FileCreateOptionsFlags::FILE_OPEN_REPARSE_POINT) != 0u) {
        result << "FILE_OPEN_REPARSE_POINT" << separator;
    }
    if ((value & FileCreateOptionsFlags::FILE_OPEN_NO_RECALL) != 0u) {
        result << "FILE_OPEN_NO_RECALL" << separator;
    }
    if ((value & FileCreateOptionsFlags::FILE_OPEN_FOR_FREE_SPACE_QUERY) != 0u) {
        result << "FILE_OPEN_FOR_FREE_SPACE_QUERY" << separator;
    }

    std::string resultStr = result.str();

    // Remove the trailing separator if one exists
    if (!resultStr.empty() != 0u) {
        return resultStr.substr(0, resultStr.size() - separator.size());
    }

    return resultStr;
}

std::string to_string(const FileCreateOptions& options, const std::string& separator) {
    return options.to_string(separator);
}

} /* namespace nt */
} /* namespace windows */
} /* namespace introvirt */
