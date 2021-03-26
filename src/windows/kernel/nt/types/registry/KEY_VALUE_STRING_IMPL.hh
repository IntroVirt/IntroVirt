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
#pragma once

#include "KEY_VALUE_IMPL.hh"

#include <introvirt/core/memory/guest_ptr.hh>
#include <introvirt/windows/common/Utf16String.hh>
#include <introvirt/windows/kernel/nt/types/registry/KEY_VALUE_STRING.hh>

#include <boost/io/ios_state.hpp>

#include <optional>

namespace introvirt {
namespace windows {
namespace nt {

template <typename _BaseClass = KEY_VALUE_STRING>
class KEY_VALUE_STRING_IMPL : public KEY_VALUE_IMPL<_BaseClass> {
  public:
    std::string StringValue() const override { return Value_; }

    void write(std::ostream& os, const std::string& linePrefix = "") const override {
        KEY_VALUE_IMPL<_BaseClass>::write(os, linePrefix);
        boost::io::ios_flags_saver ifs(os);
        os << linePrefix << "Value: " << StringValue() << '\n';
    }
    Json::Value json() const override {
        Json::Value result = KEY_VALUE_IMPL<_BaseClass>::json();
        result["StringValue"] = StringValue();
        return result;
    }

    KEY_VALUE_STRING_IMPL(const guest_ptr<void>& ptr, uint32_t size)
        : KEY_VALUE_STRING_IMPL(REG_TYPE::REG_SZ, ptr, size) {}

  protected:
    // We did it this way for KEY_VALUE_EXPAND_STRING to inherit
    KEY_VALUE_STRING_IMPL(REG_TYPE type, const guest_ptr<void>& ptr, uint32_t size)
        : KEY_VALUE_IMPL<_BaseClass>(type, ptr, size) {

        Value_ = Utf16String::convert(
            std::u16string_view(reinterpret_cast<const char16_t*>(this->buf_.get()),
                                this->buf_.length() / sizeof(char16_t)));
    }

  private:
    std::string Value_;
};

} // namespace nt
} // namespace windows
} // namespace introvirt