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
#include "FILE_RENAME_INFORMATION_IMPL.hh"

#include <introvirt/core/exception/BufferTooSmallException.hh>
#include <introvirt/util/compiler.hh>

#include <boost/io/ios_state.hpp>

namespace introvirt {
namespace windows {
namespace nt {

template <typename PtrType>
void FILE_RENAME_INFORMATION_IMPL<PtrType>::write(std::ostream& os,
                                                  const std::string& linePrefix) const {
    boost::io::ios_flags_saver ifs(os);

    os << std::hex;

    os << linePrefix << "FileInformationClass: " << FileInformationClass() << '\n';
    os << linePrefix << "ReplaceIfExists: " << ReplaceIfExists() << '\n';
    os << linePrefix << "RootDirectory: 0x" << RootDirectory() << '\n';
    os << linePrefix << "FileName: " << FileName() << '\n';
}

template <typename PtrType>
Json::Value FILE_RENAME_INFORMATION_IMPL<PtrType>::json() const {
    Json::Value result;
    result["FileInformationClass"] = to_string(FileInformationClass());
    result["ReplaceIfExists"] = ReplaceIfExists();
    result["RootDirectory"] = RootDirectory();
    result["FileName"] = FileName();
    return result;
}

template <typename PtrType>
FILE_RENAME_INFORMATION_IMPL<PtrType>::FILE_RENAME_INFORMATION_IMPL(const GuestVirtualAddress& gva,
                                                                    uint32_t buffer_size)
    : gva_(gva), buffer_size_(buffer_size) {

    if (unlikely(buffer_size < sizeof(structs::_FILE_RENAME_INFORMATION<PtrType>)))
        throw BufferTooSmallException(sizeof(structs::_FILE_RENAME_INFORMATION<PtrType>),
                                      buffer_size);

    data_.reset(gva_);

    const auto pFileName = gva_ + offsetof(structs::_FILE_RENAME_INFORMATION<PtrType>, FileName);
    buffer_size -= sizeof(structs::_FILE_RENAME_INFORMATION<PtrType>);

    const uint32_t FileNameLength = std::min(data_->FileNameLength, buffer_size);
    FileName_.emplace(pFileName, FileNameLength, buffer_size);
}

template class FILE_RENAME_INFORMATION_IMPL<uint32_t>;
template class FILE_RENAME_INFORMATION_IMPL<uint64_t>;

} // namespace nt
} // namespace windows
} // namespace introvirt