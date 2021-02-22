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
#include "KEY_VALUE_EXPAND_STRING_IMPL.hh"

namespace introvirt {
namespace windows {
namespace nt {

std::string KEY_VALUE_EXPAND_STRING_IMPL::ExpandedStringValue() const {
    // TODO(papes): Implement expansion
    // We need the current process's environmental variables to do so
    return StringValue();
}

void KEY_VALUE_EXPAND_STRING_IMPL::write(std::ostream& os, const std::string& linePrefix) const {
    KEY_VALUE_STRING_IMPL<KEY_VALUE_EXPAND_STRING>::write(os, linePrefix);

    if (!ExpandedStringValue().empty()) {
        os << linePrefix << "Expanded: " << ExpandedStringValue() << '\n';
    }
}

Json::Value KEY_VALUE_EXPAND_STRING_IMPL::json() const {
    Json::Value result = KEY_VALUE_STRING_IMPL<KEY_VALUE_EXPAND_STRING>::json();
    result["ExpandedStringValue"] = ExpandedStringValue();
    return result;
}

KEY_VALUE_EXPAND_STRING_IMPL::KEY_VALUE_EXPAND_STRING_IMPL(const GuestVirtualAddress& gva,
                                                           uint32_t size)
    : KEY_VALUE_STRING_IMPL<KEY_VALUE_EXPAND_STRING>(REG_TYPE::REG_EXPAND_SZ, gva, size) {}

} /* namespace nt */
} /* namespace windows */
} /* namespace introvirt */
