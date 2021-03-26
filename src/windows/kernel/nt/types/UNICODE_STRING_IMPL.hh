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

#include "windows/kernel/nt/NtKernelImpl.hh"

#include <introvirt/core/exception/BufferTooSmallException.hh>
#include <introvirt/util/HexDump.hh> // TODO: Remove
#include <introvirt/windows/kernel/nt/types/UNICODE_STRING.hh>

namespace introvirt {
namespace windows {
namespace nt {

namespace structs {

template <typename PtrType>
struct __attribute__((__aligned__(sizeof(PtrType)), __ms_struct__)) _UNICODE_STRING {
    uint16_t Length;
    uint16_t MaximumLength;
    PtrType Buffer; // Have to mask off the bottom bits to get the address
};

static_assert(sizeof(_UNICODE_STRING<uint32_t>) == 0x8);
static_assert(sizeof(_UNICODE_STRING<uint64_t>) == 0x10);
static_assert(offsetof(_UNICODE_STRING<uint32_t>, Buffer) == 0x4);
static_assert(offsetof(_UNICODE_STRING<uint64_t>, Buffer) == 0x8);

} // namespace structs

template <typename PtrType>
class UNICODE_STRING_IMPL final : public UNICODE_STRING {
    using _UNICODE_STRING = structs::_UNICODE_STRING<PtrType>;

  public:
    uint16_t Length() const override { return ptr_->Length; }
    void Length(uint16_t Length) override {
        ptr_->Length = Length;
        buffer_.reset();
        invalidate();
    };

    uint16_t MaximumLength() const override { return ptr_->MaximumLength; }
    void MaximumLength(uint16_t MaximumLength) override {
        ptr_->MaximumLength = MaximumLength;
        invalidate();
    }

    guest_ptr<void> BufferAddress() const override {
        return ptr_.clone(ptr_->Buffer & 0xFFFFFFFFFFFFFFFELL);
    }
    void BufferAddress(const guest_ptr<void>& ptr) override {
        ptr_->Buffer = ptr.address();
        buffer_.reset();
        invalidate();
    }

    const uint8_t* Buffer() const override {
        if (!buffer_.get() && BufferAddress() && Length()) {
            buffer_.reset(BufferAddress(), Length());
        }
        return buffer_.get();
    }

    void set(const std::u16string& value) override {
        const size_t new_length = value.length() * sizeof(char16_t);

        // Does it fit into the UNICODE_STRING?
        if (unlikely(new_length > MaximumLength())) {
            throw BufferTooSmallException(new_length, MaximumLength());
        }

        // Does it fit into the current mapping?
        if (new_length > buffer_.length()) {
            // No, remap the buffer.
            buffer_.reset(BufferAddress(), new_length);
        }

        // Copy the data
        std::memcpy(buffer_.get(), value.data(), new_length);

        // Update the Length field
        Length(new_length);
    }
    using Utf16String::set;

    Json::Value json() const override {
        Json::Value result(Utf16String::json());
        result["BufferAddress"] = ptr_->Buffer;
        result["Length"] = Length();
        result["MaximumLength"] = MaximumLength();
        return result;
    }

    guest_ptr<void> ptr() const override { return ptr_; }

    UNICODE_STRING_IMPL(const guest_ptr<void>& ptr) : ptr_(ptr) {}

    UNICODE_STRING_IMPL(guest_ptr<_UNICODE_STRING>&& ptr) : ptr_(std::move(ptr)) {}

    ~UNICODE_STRING_IMPL() override;

  private:
    guest_ptr<_UNICODE_STRING> ptr_;
    mutable guest_ptr<uint8_t[]> buffer_;
};

} // namespace nt
} // namespace windows
} // namespace introvirt