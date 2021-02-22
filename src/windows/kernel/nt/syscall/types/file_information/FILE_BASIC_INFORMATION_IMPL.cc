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
#include "FILE_BASIC_INFORMATION_IMPL.hh"

#include <introvirt/core/exception/BufferTooSmallException.hh>
#include <introvirt/util/compiler.hh>
#include <introvirt/windows/util/WindowsTime.hh>

#include <boost/io/ios_state.hpp>

namespace introvirt {
namespace windows {
namespace nt {

void FILE_BASIC_INFORMATION_IMPL::write(std::ostream& os, const std::string& linePrefix) const {
    boost::io::ios_flags_saver ifs(os);
    os << std::dec;

    os << linePrefix << "FileInformationClass: " << FileInformationClass() << '\n';
    os << linePrefix << "CreationTime:   " << CreationTime() << '\n';
    os << linePrefix << "LastAccessTime: " << LastAccessTime() << '\n';
    os << linePrefix << "LastWriteTime:  " << LastWriteTime() << '\n';
    os << linePrefix << "ChangeTime:     " << ChangeTime() << '\n';
    os << linePrefix << "Attributes:     " << FileAttributes().dir_string() << '\n';
}

Json::Value FILE_BASIC_INFORMATION_IMPL::json() const {
    Json::Value result;
    result["FileInformationClass"] = to_string(FileInformationClass());
    result["CreationTime"] = CreationTime().unix_time();
    result["LastAccessTime"] = LastAccessTime().unix_time();
    result["LastWriteTime"] = LastWriteTime().unix_time();
    result["ChangeTime"] = ChangeTime().unix_time();
    result["FileAttributes"] = FileAttributes().json();
    return result;
}

FILE_BASIC_INFORMATION_IMPL::FILE_BASIC_INFORMATION_IMPL(const GuestVirtualAddress& gva)
    : FILE_BASIC_INFORMATION_IMPL(gva, sizeof(structs::_FILE_BASIC_INFORMATION)) {}

FILE_BASIC_INFORMATION_IMPL::FILE_BASIC_INFORMATION_IMPL(const GuestVirtualAddress& gva,
                                                         uint32_t buffer_size)
    : gva_(gva), buffer_size_(buffer_size) {

    if (unlikely(buffer_size < sizeof(structs::_FILE_BASIC_INFORMATION)))
        throw BufferTooSmallException(sizeof(structs::_FILE_BASIC_INFORMATION), buffer_size);

    data_.reset(gva_);
}

std::unique_ptr<FILE_BASIC_INFORMATION>
FILE_BASIC_INFORMATION::make_unique(const GuestVirtualAddress& gva) {
    return std::make_unique<FILE_BASIC_INFORMATION_IMPL>(gva,
                                                         sizeof(structs::_FILE_BASIC_INFORMATION));
}

} // namespace nt
} // namespace windows
} // namespace introvirt