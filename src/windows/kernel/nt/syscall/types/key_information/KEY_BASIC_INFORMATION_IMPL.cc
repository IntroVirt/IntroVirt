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
#include "KEY_BASIC_INFORMATION_IMPL.hh"

#include <introvirt/core/exception/BufferTooSmallException.hh>

#include <boost/io/ios_state.hpp>

namespace introvirt {
namespace windows {
namespace nt {

void KEY_BASIC_INFORMATION_IMPL::write(std::ostream& os, const std::string& linePrefix) const {
    boost::io::ios_flags_saver ifs(os);
    os << std::dec;

    os << linePrefix << "KeyInformationClass: " << KeyInformationClass() << '\n';
    os << linePrefix << "Name: " << Name() << '\n';
    os << linePrefix << "LastWriteTime: " << LastWriteTime() << '\n';
    os << linePrefix << "TitleIndex: " << TitleIndex() << '\n';
}

Json::Value KEY_BASIC_INFORMATION_IMPL::json() const {
    Json::Value result;
    result["KeyInformationClass"] = to_string(KeyInformationClass());
    result["Name"] = Name();
    result["LastWriteTime"] = LastWriteTime().unix_time();
    result["TitleIndex"] = TitleIndex();
    return result;
}

KEY_BASIC_INFORMATION_IMPL::KEY_BASIC_INFORMATION_IMPL(const GuestVirtualAddress& gva,
                                                       uint32_t buffer_size)
    : gva_(gva), buffer_size_(buffer_size) {

    if (unlikely(buffer_size < sizeof(structs::_KEY_BASIC_INFORMATION)))
        throw BufferTooSmallException(sizeof(structs::_KEY_BASIC_INFORMATION), buffer_size);

    data_.reset(gva_);

    const auto pName = gva_ + offsetof(structs::_KEY_BASIC_INFORMATION, Name);
    const uint32_t name_buffer_len = (gva_ + buffer_size) - pName;
    const uint32_t name_length = std::min(data_->NameLength, name_buffer_len);
    Name_.emplace(pName, name_length, name_buffer_len);
}

} // namespace nt
} // namespace windows
} // namespace introvirt