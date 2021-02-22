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
#include "KEY_VALUE_STRING_IMPL.hh"

#include <boost/io/ios_state.hpp>

#include <introvirt/windows/kernel/nt/types/registry/KEY_VALUE_EXPAND_STRING.hh>

namespace introvirt {
namespace windows {
namespace nt {

template <typename _BaseClass>
std::string KEY_VALUE_STRING_IMPL<_BaseClass>::StringValue() const {
    if (unlikely(!Value_))
        return std::string();

    return Value_->utf8();
}

template <typename _BaseClass>
void KEY_VALUE_STRING_IMPL<_BaseClass>::write(std::ostream& os,
                                              const std::string& linePrefix) const {
    KEY_VALUE_IMPL<_BaseClass>::write(os, linePrefix);
    boost::io::ios_flags_saver ifs(os);
    os << linePrefix << "Value: " << StringValue() << '\n';
}

template <typename _BaseClass>
Json::Value KEY_VALUE_STRING_IMPL<_BaseClass>::json() const {
    Json::Value result = KEY_VALUE_IMPL<_BaseClass>::json();
    result["StringValue"] = StringValue();
    return result;
}

template <typename _BaseClass>
KEY_VALUE_STRING_IMPL<_BaseClass>::KEY_VALUE_STRING_IMPL(const GuestVirtualAddress& gva,
                                                         uint32_t size)
    : KEY_VALUE_STRING_IMPL(REG_TYPE::REG_SZ, gva, size) {}

template <typename _BaseClass>
KEY_VALUE_STRING_IMPL<_BaseClass>::KEY_VALUE_STRING_IMPL(REG_TYPE type,
                                                         const GuestVirtualAddress& gva,
                                                         uint32_t size)
    : KEY_VALUE_IMPL<_BaseClass>(type, gva, size) {

    Value_.emplace(this->address(), this->DataSize());
}

template class KEY_VALUE_STRING_IMPL<KEY_VALUE_STRING>;
template class KEY_VALUE_STRING_IMPL<KEY_VALUE_EXPAND_STRING>;

} // namespace nt
} // namespace windows
} /* namespace introvirt */
