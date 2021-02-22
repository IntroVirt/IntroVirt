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
#include "KEY_NODE_INFORMATION_IMPL.hh"

#include <introvirt/core/exception/BufferTooSmallException.hh>

#include <boost/io/ios_state.hpp>

namespace introvirt {
namespace windows {
namespace nt {

void KEY_NODE_INFORMATION_IMPL::write(std::ostream& os, const std::string& linePrefix) const {
    boost::io::ios_flags_saver ifs(os);
    os << std::hex;
    os << linePrefix << "KeyInformationClass: " << KeyInformationClass() << '\n';
    os << linePrefix << "Name: " << Name() << '\n';
    os << linePrefix << "Class: " << Class() << '\n';
    os << linePrefix << "LastWriteTime: " << LastWriteTime() << '\n';
    os << linePrefix << "TitleIndex: " << TitleIndex() << '\n';
}

Json::Value KEY_NODE_INFORMATION_IMPL::json() const {
    Json::Value result;
    result["KeyInformationClass"] = to_string(KeyInformationClass());
    result["Name"] = Name();
    result["Class"] = Class();
    result["LastWriteTime"] = LastWriteTime().unix_time();
    result["TitleIndex"] = TitleIndex();
    return result;
}

KEY_NODE_INFORMATION_IMPL::KEY_NODE_INFORMATION_IMPL(const GuestVirtualAddress& gva,
                                                     uint32_t buffer_size)
    : gva_(gva), buffer_size_(buffer_size) {

    if (unlikely(buffer_size < sizeof(structs::_KEY_NODE_INFORMATION)))
        throw BufferTooSmallException(sizeof(structs::_KEY_NODE_INFORMATION), buffer_size);

    data_.reset(gva_);

    const auto pName = gva_ + offsetof(structs::_KEY_NODE_INFORMATION, Name);
    const uint32_t name_buffer_len = (gva_ + data_->ClassOffset) - pName;
    const uint32_t name_length = std::min(data_->NameLength, name_buffer_len);
    Name_.emplace(pName, name_length, name_buffer_len);

    if (data_->ClassOffset && data_->ClassLength) {
        const auto pClass = gva_ + data_->ClassOffset;
        const uint32_t class_buffer_len = (gva_ + buffer_size) - pClass;
        const uint32_t class_length = std::min(data_->ClassLength, class_buffer_len);
        ClassName_.emplace(pClass, class_length, class_buffer_len);
    } else {
        ClassName_.emplace(NullGuestAddress(), 0, 0);
    }
}

} // namespace nt
} // namespace windows
} // namespace introvirt