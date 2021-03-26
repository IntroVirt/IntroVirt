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

#include <introvirt/windows/common/WStr.hh>

#include <introvirt/core/exception/VirtualAddressNotPresentException.hh>
#include <introvirt/util/compiler.hh>
#include <introvirt/util/introvirt_assert.hh>
#include <introvirt/windows/exception/StringConversionException.hh>

#include <boost/algorithm/string/predicate.hpp>
#include <boost/locale.hpp>

#include <cassert>

namespace introvirt {
namespace windows {

guest_ptr<void> WStr::ptr() const { return buf_; }

WStr::WStr(const guest_ptr<void>& ptr)
    : buf_(map_guest_wstring(ptr)), len_(buf_.length() * sizeof(char16_t)) {}

WStr::WStr(const guest_ptr<void>& ptr, size_t buffer_size)
    : buf_(ptr, buffer_size / sizeof(char16_t)) {

    // Determine the length of the string
    size_t len;
    for (len = 0; len < buf_.length() && buf_[len]; ++len) {
    }

    len_ = len * sizeof(char16_t);
}

WStr::WStr(const guest_ptr<void>& ptr, size_t buffer_size, size_t len)
    : buf_(ptr, buffer_size / sizeof(char16_t)), len_(len) {
    introvirt_assert(buffer_size >= len, "Length too small for buffer");
}

uint16_t WStr::Length() const { return len_; }
uint16_t WStr::MaximumLength() const { return buf_.length() * sizeof(char16_t); }
const uint8_t* WStr::Buffer() const { return reinterpret_cast<const uint8_t*>(buf_.get()); }

void WStr::set(const std::u16string& value) {
    // Zero the buffer
    std::memset(buf_.get(), 0, buf_.length());

    // Copy in our data
    const size_t copy_size = value.length() * sizeof(char16_t);
    if (unlikely(copy_size > buf_.length())) {
        throw StringConversionException("Buffer too small for string data");
    }

    std::memcpy(buf_.get(), value.data(), copy_size);

    // Update the length
    len_ = copy_size;
    invalidate();
}

WStr::WStr(WStr&&) noexcept = default;
WStr& WStr::operator=(WStr&&) noexcept = default;
WStr::~WStr() = default;

} /* namespace windows */
} /* namespace introvirt */
