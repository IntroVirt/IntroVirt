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
#include "KEY_VALUE_MULTI_STRING_IMPL.hh"

#include <boost/io/ios_state.hpp>
#include <introvirt/windows/common/Utf16String.hh>

#include <memory>

namespace introvirt {
namespace windows {
namespace nt {

const std::vector<std::string>& KEY_VALUE_MULTI_STRING_IMPL::StringValues() const {
    return Values_;
}

void KEY_VALUE_MULTI_STRING_IMPL::write(std::ostream& os, const std::string& linePrefix) const {
    KEY_VALUE_IMPL<KEY_VALUE_MULTI_STRING>::write(os, linePrefix);
    boost::io::ios_flags_saver ifs(os);

    bool first = true;
    for (const auto& str : Values_) {
        os << linePrefix;
        if (!first) {
            os << '\t';
        } else {
            os << "Values:\t";
            first = false;
        }
        os << str << '\n';
    }
}

Json::Value KEY_VALUE_MULTI_STRING_IMPL::json() const {
    Json::Value result = KEY_VALUE_IMPL<KEY_VALUE_MULTI_STRING>::json();
    for (const auto& str : Values_) {
        result["StringValues"].append(str);
    }
    return result;
}

KEY_VALUE_MULTI_STRING_IMPL::KEY_VALUE_MULTI_STRING_IMPL(const guest_ptr<void>& ptr, uint32_t size)
    : KEY_VALUE_IMPL<KEY_VALUE_MULTI_STRING>(REG_TYPE::REG_MULTI_SZ, ptr, size) {

    const char* data = reinterpret_cast<const char*>(buf_.get());

    // Several null terminated unicode strings
    uint32_t currentStringStart = 0;
    for (uint32_t i = 1; i < size; ++i) {
        if (data[i - 1] == '\0' && data[i] == '\0') {
            // We've reached the end of a string
            const char16_t* startAddress =
                reinterpret_cast<const char16_t*>(data + currentStringStart);
            uint16_t length = i - currentStringStart;
            if (length != 0) {
                std::u16string_view view(startAddress, length);
                Values_.emplace_back(Utf16String::convert(view));
            }
            currentStringStart = i + 1;
        }
    }
}

} /* namespace nt */
} /* namespace windows */
} /* namespace introvirt */
