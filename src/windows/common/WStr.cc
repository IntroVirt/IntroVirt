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

#include <introvirt/core/exception/VirtualAddressNotPresentException.hh>
#include <introvirt/core/memory/GuestVirtualAddress.hh>
#include <introvirt/core/memory/guest_ptr.hh>
#include <introvirt/util/compiler.hh>
#include <introvirt/windows/common/WStr.hh>
#include <introvirt/windows/exception/StringConversionException.hh>

#include <boost/algorithm/string/predicate.hpp>
#include <boost/locale.hpp>

#include <cassert>

namespace introvirt {
namespace windows {

class WStr::IMPL {
  public:
    IMPL(const GuestVirtualAddress& gva) : gva_(gva) {
        // Map and determine the length of the string
        auto wstr = map_guest_wstr(gva);
        length_ = wstr.length() * sizeof(char16_t);

        // TODO: Would be nice if we didn't have to re-map
        buf_.reset(gva_, length_);
    }

    IMPL(const GuestVirtualAddress& gva, size_t buffer_size) : gva_(gva), length_(buffer_size) {
        if (buffer_size == 0)
            return;
        buf_.reset(gva, buffer_size);

        const auto* buf = reinterpret_cast<const char16_t*>(buf_.get());

        // Search the buffer for a null terminator
        for (unsigned int i = 0; i < (buf_.length() / 2); i++) {
            if (buf[i] == 0) {
                length_ = i * 2;
                break;
            }
        }
    }

    IMPL(const GuestVirtualAddress& gva, size_t length, size_t buffer_size)
        : gva_(gva), length_(length) {

        assert(buffer_size >= length);

        if (buffer_size == 0)
            return;

        try {
            buf_.reset(gva_, buffer_size);
        } catch (VirtualAddressNotPresentException& ex) {
            // Try again, but this time use the length rather than the buffer size.
            // This is only a problem when trying to call "set", the buffer will be smaller.
            if (length > 0)
                buf_.reset(gva, length);
        }
    }

    IMPL(guest_ptr<uint8_t[]>&& src, size_t len) : buf_(std::move(src)) {
        if (len == 0)
            len = buf_.length();

        length_ = len;
    }

  public:
    GuestVirtualAddress gva_;
    guest_ptr<uint8_t[]> buf_;
    size_t length_;
};

GuestVirtualAddress WStr::address() const { return pImpl_->gva_; }

WStr::WStr(const GuestVirtualAddress& gva) : pImpl_(std::make_unique<IMPL>(gva)) {}

WStr::WStr(const GuestVirtualAddress& gva, size_t buffer_size)
    : pImpl_(std::make_unique<IMPL>(gva, buffer_size)) {}

WStr::WStr(const GuestVirtualAddress& gva, size_t len, size_t buffer_size)
    : pImpl_(std::make_unique<IMPL>(gva, len, buffer_size)) {}

WStr::WStr(guest_ptr<uint8_t[]>&& src, size_t len)
    : pImpl_(std::make_unique<IMPL>(std::move(src), len)) {}

uint16_t WStr::Length() const { return pImpl_->length_; }

uint16_t WStr::MaximumLength() const { return pImpl_->buf_.length(); }

const uint8_t* WStr::Buffer() const { return reinterpret_cast<const uint8_t*>(pImpl_->buf_.get()); }

void WStr::set(const std::u16string& value) {
    const size_t buffer_size = pImpl_->buf_.length();

    // Zero the buffer
    std::memset(pImpl_->buf_.get(), 0, buffer_size);

    // Copy in our data
    const size_t copy_size = value.length() * sizeof(char16_t);

    if (unlikely(copy_size > pImpl_->buf_.length())) {
        throw StringConversionException("Buffer too small for string data");
    }

    std::memcpy(pImpl_->buf_.get(), value.data(), copy_size);

    // Update the length
    pImpl_->length_ = copy_size;

    invalidate();
}

WStr::WStr(WStr&&) noexcept = default;
WStr& WStr::operator=(WStr&&) noexcept = default;
WStr::~WStr() = default;

} /* namespace windows */
} /* namespace introvirt */
