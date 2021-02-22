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
#include "FILE_BOTH_DIR_INFORMATION_IMPL.hh"

#include <introvirt/core/exception/BufferTooSmallException.hh>
#include <introvirt/util/compiler.hh>

#include <boost/io/ios_state.hpp>

namespace introvirt {
namespace windows {
namespace nt {

void FILE_BOTH_DIR_INFORMATION_IMPL::write(std::ostream& os, const std::string& linePrefix) const {
    boost::io::ios_flags_saver ifs(os);
    os << std::dec;

    os << linePrefix << "FileInformationClass: " << to_string(FileInformationClass()) << '\n';

    for (const auto& entry : *this) {
        os << linePrefix << "\tFileName: " << entry.FileName() << '\n';
        os << linePrefix << "\t\tShortName: " << entry.ShortName() << '\n';
        os << linePrefix << "\t\tFileIndex: " << entry.FileIndex() << '\n';
        os << linePrefix << "\t\tCreationTime: " << entry.CreationTime() << '\n';
        os << linePrefix << "\t\tLastAccessTime: " << entry.LastAccessTime() << '\n';
        os << linePrefix << "\t\tLastWriteTime: " << entry.LastWriteTime() << '\n';
        os << linePrefix << "\t\tChangeTime: " << entry.ChangeTime() << '\n';
        os << linePrefix << "\t\tEndOfFile: " << entry.EndOfFile() << '\n';
        os << linePrefix << "\t\tAllocationSize: " << entry.AllocationSize() << '\n';
        os << linePrefix << "\t\tFileAttributes: " << entry.FileAttributes().dir_string() << '\n';
        os << linePrefix << "\t\tEaSize: " << entry.EaSize() << '\n';
    }
}

Json::Value FILE_BOTH_DIR_INFORMATION_IMPL::json() const {
    Json::Value result;
    result["FileInformationClass"] = to_string(FileInformationClass());

    Json::Value entries;
    for (const auto& entry : *this) {
        Json::Value json_entry;
        json_entry["FileName"] = entry.FileName();
        json_entry["FileIndex"] = entry.FileIndex();
        json_entry["CreationTime"] = entry.CreationTime().unix_time();
        json_entry["LastAccessTime"] = entry.LastAccessTime().unix_time();
        json_entry["LastWriteTime"] = entry.LastWriteTime().unix_time();
        json_entry["ChangeTime"] = entry.ChangeTime().unix_time();
        json_entry["EndOfFile"] = entry.EndOfFile();
        json_entry["AllocationSize"] = entry.AllocationSize();
        json_entry["FileAttributes"] = entry.FileAttributes().json();
        json_entry["EaSize"] = entry.EaSize();
        json_entry["ShortName"] = entry.ShortName();
        entries.append(std::move(json_entry));
    }

    result["entries"] = std::move(entries);

    return result;
}

FILE_BOTH_DIR_INFORMATION_IMPL::FILE_BOTH_DIR_INFORMATION_IMPL(const GuestVirtualAddress& gva,
                                                               uint32_t buffer_size)
    : offset_iterable(
          [](const GuestVirtualAddress& gva, uint32_t buffer_size) {
              return std::make_shared<FILE_BOTH_DIR_INFORMATION_ENTRY_IMPL>(gva);
          },
          gva, buffer_size) {

    if (unlikely(buffer_size < sizeof(structs::_FILE_BOTH_DIR_INFORMATION)))
        throw BufferTooSmallException(sizeof(structs::_FILE_BOTH_DIR_INFORMATION), buffer_size);
}

std::shared_ptr<FILE_BOTH_DIR_INFORMATION_ENTRY>
FILE_BOTH_DIR_INFORMATION_ENTRY::make_shared(const GuestVirtualAddress& gva) {
    return std::make_shared<FILE_BOTH_DIR_INFORMATION_ENTRY_IMPL>(gva);
}

} // namespace nt
} // namespace windows
} // namespace introvirt