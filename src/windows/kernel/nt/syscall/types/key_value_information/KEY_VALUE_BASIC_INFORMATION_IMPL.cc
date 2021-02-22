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
#include "KEY_VALUE_BASIC_INFORMATION_IMPL.hh"

namespace introvirt {
namespace windows {
namespace nt {

void KEY_VALUE_BASIC_INFORMATION_IMPL::write(std::ostream& os,
                                             const std::string& linePrefix) const {

    KEY_VALUE_BASIC_INFORMATION_IMPL_BASE::write(os, linePrefix);
    os << linePrefix << "Name: " << Name() << '\n';
}

Json::Value KEY_VALUE_BASIC_INFORMATION_IMPL::json() const {
    Json::Value result = KEY_VALUE_BASIC_INFORMATION_IMPL_BASE::json();
    result["Name"] = Name();
    return result;
}

KEY_VALUE_BASIC_INFORMATION_IMPL::KEY_VALUE_BASIC_INFORMATION_IMPL(const GuestVirtualAddress& gva,
                                                                   uint32_t buffer_size)
    : KEY_VALUE_BASIC_INFORMATION_IMPL_BASE(KEY_VALUE_INFORMATION_CLASS::KeyValueBasicInformation,
                                            gva, buffer_size) {

    const auto pName = gva_ + offsetof(structs::_KEY_VALUE_BASIC_INFORMATION, Name);
    const uint32_t name_buffer_len = (gva_ + buffer_size) - pName;
    const uint32_t name_length = std::min(data_->NameLength, name_buffer_len);
    Name_.emplace(pName, name_length, name_buffer_len);
}

} // namespace nt
} // namespace windows
} // namespace introvirt