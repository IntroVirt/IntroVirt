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
#include "KEY_CACHED_INFORMATION_IMPL.hh"

#include <introvirt/core/exception/BufferTooSmallException.hh>

#include <boost/io/ios_state.hpp>

namespace introvirt {
namespace windows {
namespace nt {

void KEY_CACHED_INFORMATION_IMPL::write(std::ostream& os, const std::string& linePrefix) const {
    boost::io::ios_flags_saver ifs(os);
    os << std::dec;
    os << linePrefix << "KeyInformationClass: " << KeyInformationClass() << '\n';

    os << linePrefix << "LastWriteTime: " << LastWriteTime() << '\n';
    os << linePrefix << "TitleIndex: " << TitleIndex() << '\n';
    os << linePrefix << "SubKeyCount: " << SubKeyCount() << '\n';
    os << linePrefix << "MaxNameLen: " << MaxNameLen() << '\n';
    os << linePrefix << "ValueCount: " << ValueCount() << '\n';
    os << linePrefix << "MaxValueNameLen: " << MaxValueNameLen() << '\n';
    os << linePrefix << "MaxValueDataLen: " << MaxValueDataLen() << '\n';
    os << linePrefix << "NameLen: " << NameLen() << '\n';
}

Json::Value KEY_CACHED_INFORMATION_IMPL::json() const {
    Json::Value result;
    result["KeyInformationClass"] = to_string(KeyInformationClass());

    result["LastWriteTime"] = LastWriteTime().unix_time();
    result["TitleIndex"] = TitleIndex();
    result["SubKeyCount"] = SubKeyCount();
    result["MaxNameLen"] = MaxNameLen();
    result["ValueCount"] = ValueCount();
    result["MaxValueNameLen"] = MaxValueNameLen();
    result["MaxValueDataLen"] = MaxValueDataLen();
    result["NameLen"] = NameLen();

    return result;
}

KEY_CACHED_INFORMATION_IMPL::KEY_CACHED_INFORMATION_IMPL(const guest_ptr<void>& ptr,
                                                         uint32_t buffer_size)
    : buffer_size_(buffer_size) {

    if (unlikely(buffer_size < sizeof(structs::_KEY_CACHED_INFORMATION)))
        throw BufferTooSmallException(sizeof(structs::_KEY_CACHED_INFORMATION), buffer_size);

    ptr_.reset(ptr);
}

} // namespace nt
} // namespace windows
} // namespace introvirt