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
#include "KEY_VALUE_FULL_INFORMATION_IMPL.hh"

namespace introvirt {
namespace windows {
namespace nt {

void KEY_VALUE_FULL_INFORMATION_IMPL::write(std::ostream& os, const std::string& linePrefix) const {
    KEY_VALUE_FULL_INFORMATION_IMPL_BASE::write(os, linePrefix);

    os << linePrefix << "Name: " << Name() << '\n';
    if (Data()) {
        os << linePrefix << "Data: " << '\n';
        Data()->write(os, linePrefix + "  ");
    }
}

Json::Value KEY_VALUE_FULL_INFORMATION_IMPL::json() const {
    Json::Value result = KEY_VALUE_FULL_INFORMATION_IMPL_BASE::json();
    result["Name"] = Name();
    if (Data()) {
        result["Data"] = Data()->json();
    }
    return result;
}

KEY_VALUE_FULL_INFORMATION_IMPL::KEY_VALUE_FULL_INFORMATION_IMPL(const GuestVirtualAddress& gva,
                                                                 uint32_t buffer_size)
    : KEY_VALUE_FULL_INFORMATION_IMPL_BASE(KEY_VALUE_INFORMATION_CLASS::KeyValueFullInformation,
                                           gva, buffer_size) {

    const auto pName = gva_ + offsetof(structs::_KEY_VALUE_FULL_INFORMATION, Name);
    const uint32_t name_buffer_len = (gva_ + data_->DataOffset) - pName;
    const uint32_t name_length = std::min(data_->NameLength, name_buffer_len);
    Name_.emplace(pName, name_length, name_buffer_len);

    if (data_->DataOffset && data_->DataLength) {
        const auto pData = gva_ + data_->DataOffset;
        const uint32_t data_buffer_len = (gva_ + buffer_size) - pData;
        if (likely(data_->DataLength >= data_buffer_len)) {
            Data_ = KEY_VALUE::make_unique(Type(), pData, data_->DataLength);
        }
    }
}

} // namespace nt
} // namespace windows
} // namespace introvirt