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
#include "FILE_STREAM_INFORMATION_IMPL.hh"

#include <introvirt/core/exception/BufferTooSmallException.hh>
#include <introvirt/core/exception/InvalidMethodException.hh>
#include <introvirt/util/compiler.hh>

#include <boost/io/ios_state.hpp>

namespace introvirt {
namespace windows {
namespace nt {

void FILE_STREAM_INFORMATION_IMPL::write(std::ostream& os, const std::string& linePrefix) const {
    boost::io::ios_flags_saver ifs(os);
    os << std::dec;

    os << linePrefix << "FileInformationClass: " << FileInformationClass() << '\n';

    for (const auto& entry : *this) {
        os << linePrefix << "\tStreamName: " << entry.StreamName() << '\n';
        os << linePrefix << "\t\tStreamSize: " << entry.StreamSize() << '\n';
        os << linePrefix << "\t\tStreamAllocationSize: " << entry.StreamAllocationSize() << '\n';
    }
}

Json::Value FILE_STREAM_INFORMATION_IMPL::json() const {
    Json::Value result;
    result["FileInformationClass"] = to_string(FileInformationClass());

    Json::Value entries;
    for (const auto& entry : *this) {
        Json::Value json_entry;
        json_entry["StreamName"] = entry.StreamName();
        json_entry["StreamSize"] = entry.StreamSize();
        json_entry["StreamAllocationSize"] = entry.StreamAllocationSize();
        entries.append(std::move(json_entry));
    }

    result["entries"] = std::move(entries);
    return result;
}

FILE_STREAM_INFORMATION_ENTRY_IMPL&
FILE_STREAM_INFORMATION_ENTRY_IMPL::operator=(const FILE_STREAM_INFORMATION_ENTRY& src) {
    const auto& src_impl = static_cast<const FILE_STREAM_INFORMATION_ENTRY_IMPL&>(src);
    gva_ = src_impl.gva_;
    *data_ = *(src_impl.data_);
    StreamName_ = WStr(gva_ + offsetof(structs::_FILE_STREAM_INFORMATION, StreamName),
                       src_impl.StreamName_.Length(), src_impl.StreamName_.MaximumLength());

    StreamName_.set(src_impl.StreamName_.utf16());
    return *this;
}

FILE_STREAM_INFORMATION_IMPL::FILE_STREAM_INFORMATION_IMPL(const GuestVirtualAddress& gva,
                                                           uint32_t buffer_size)
    : offset_iterable(
          [](const GuestVirtualAddress& gva, uint32_t buffer_size) {
              return std::make_shared<FILE_STREAM_INFORMATION_ENTRY_IMPL>(gva);
          },
          gva, buffer_size) {

    if (unlikely(buffer_size < sizeof(structs::_FILE_STREAM_INFORMATION)))
        throw BufferTooSmallException(sizeof(structs::_FILE_STREAM_INFORMATION), buffer_size);
}

std::shared_ptr<FILE_STREAM_INFORMATION_ENTRY>
FILE_STREAM_INFORMATION_ENTRY::make_shared(const GuestVirtualAddress& gva) {
    return std::make_shared<FILE_STREAM_INFORMATION_ENTRY_IMPL>(gva);
}

} // namespace nt
} // namespace windows
} // namespace introvirt