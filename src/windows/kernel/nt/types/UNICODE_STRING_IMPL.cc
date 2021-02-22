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
#include "UNICODE_STRING_IMPL.hh"
#include "core/event/EventImpl.hh"

#include <introvirt/core/exception/BufferTooSmallException.hh>
#include <introvirt/windows/WindowsGuest.hh>
#include <introvirt/windows/kernel/nt/NtKernel.hh>

#include <boost/algorithm/string/predicate.hpp>
#include <boost/locale.hpp>

#include <utility>

namespace introvirt {
namespace windows {
namespace nt {

template <typename PtrType>
uint16_t UNICODE_STRING_IMPL<PtrType>::Length() const {
    return header_->Length;
}

template <typename PtrType>
void UNICODE_STRING_IMPL<PtrType>::Length(uint16_t Length) {
    buffer_.reset();
    header_->Length = Length;
    invalidate();
}

template <typename PtrType>
uint16_t UNICODE_STRING_IMPL<PtrType>::MaximumLength() const {
    return header_->MaximumLength;
}

template <typename PtrType>
void UNICODE_STRING_IMPL<PtrType>::MaximumLength(uint16_t MaximumLength) {
    header_->MaximumLength = MaximumLength;
    invalidate();
}

template <typename PtrType>
GuestVirtualAddress UNICODE_STRING_IMPL<PtrType>::BufferAddress() const {
    // The bottom bit in the Buffer address is a signal of some kind
    // We need to mask that off to map it correctly
    return gva_.create(header_->Buffer & 0xFFFFFFFFFFFFFFFELL);
}

template <typename PtrType>
void UNICODE_STRING_IMPL<PtrType>::BufferAddress(const GuestVirtualAddress& pBufferAddress) {
    buffer_.reset();
    header_->Buffer = pBufferAddress.virtual_address();
    invalidate();
}

template <typename PtrType>
const uint8_t* UNICODE_STRING_IMPL<PtrType>::Buffer() const {
    if (!buffer_.get() && BufferAddress() && Length()) {
        buffer_.reset(BufferAddress(), Length());
    }
    return buffer_.get();
}

template <typename PtrType>
GuestVirtualAddress UNICODE_STRING_IMPL<PtrType>::address() const {
    return gva_;
}

template <typename PtrType>
void UNICODE_STRING_IMPL<PtrType>::set(const std::u16string& value) {
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

// Guest virtual address constructor
template <typename PtrType>
UNICODE_STRING_IMPL<PtrType>::UNICODE_STRING_IMPL(const GuestVirtualAddress& gva)
    : gva_(gva), header_(gva) {}

template <typename PtrType>
Json::Value UNICODE_STRING_IMPL<PtrType>::json() const {
    Json::Value result(Utf16String::json());
    result["BufferAddress"] = BufferAddress().json();
    result["Length"] = Length();
    result["MaximumLength"] = MaximumLength();
    return result;
}

template <typename PtrType>
UNICODE_STRING_IMPL<PtrType>::~UNICODE_STRING_IMPL() = default;

std::unique_ptr<UNICODE_STRING> UNICODE_STRING::make_unique(const NtKernel& kernel,
                                                            const GuestVirtualAddress& gva) {

    if (kernel.x64())
        return std::make_unique<UNICODE_STRING_IMPL<uint64_t>>(gva);
    else
        return std::make_unique<UNICODE_STRING_IMPL<uint32_t>>(gva);
}

template class UNICODE_STRING_IMPL<uint32_t>;
template class UNICODE_STRING_IMPL<uint64_t>;

} /* namespace nt */
} /* namespace windows */

namespace inject {

GuestAllocation<windows::nt::UNICODE_STRING>::GuestAllocation(const std::string& value)
    : GuestAllocation(value, value.length() * sizeof(char16_t)) {}

GuestAllocation<windows::nt::UNICODE_STRING>::GuestAllocation(const std::string& value,
                                                              unsigned int MaximumLength) {

    using namespace windows::nt;

    auto& domain = Domain::thread_local_domain();
    auto* guest = static_cast<windows::WindowsGuest*>(domain.guest());
    assert(guest != nullptr);
    auto& kernel = guest->kernel();

    // Get the size required for the structure
    const size_t structure_size = (kernel.x64()) ? sizeof(structs::_UNICODE_STRING<uint64_t>)
                                                 : sizeof(structs::_UNICODE_STRING<uint32_t>);

    // Allocate memory for the size of the structure plus the size of the string
    buffer_.emplace(structure_size + MaximumLength);

    // Figure out the buffer address
    GuestVirtualAddress BufferAddress = buffer_->address() + structure_size;

    // Create the string
    value_ = UNICODE_STRING::make_unique(kernel, *buffer_);
    value_->Length(value.length());
    value_->MaximumLength(MaximumLength);
    value_->BufferAddress(BufferAddress);

    value_->set(value);
}

} /* namespace inject */
} /* namespace introvirt */
