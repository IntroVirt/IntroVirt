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

#include <introvirt/windows/WindowsGuest.hh>
#include <introvirt/windows/kernel/nt/NtKernel.hh>

#include <boost/algorithm/string/predicate.hpp>
#include <boost/locale.hpp>

#include <utility>

namespace introvirt {
namespace windows {
namespace nt {

template <typename PtrType>
UNICODE_STRING_IMPL<PtrType>::~UNICODE_STRING_IMPL() = default;

std::unique_ptr<UNICODE_STRING> UNICODE_STRING::make_unique(const NtKernel& kernel,
                                                            const guest_ptr<void>& ptr) {

    if (kernel.x64())
        return std::make_unique<UNICODE_STRING_IMPL<uint64_t>>(ptr);
    else
        return std::make_unique<UNICODE_STRING_IMPL<uint32_t>>(ptr);
}

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
    introvirt_assert(guest != nullptr, "");
    auto& kernel = guest->kernel();

    // Get the size required for the structure
    const size_t structure_size = (kernel.x64()) ? sizeof(structs::_UNICODE_STRING<uint64_t>)
                                                 : sizeof(structs::_UNICODE_STRING<uint32_t>);

    // Allocate memory for the size of the structure plus the size of the string
    allocation_.emplace(structure_size + MaximumLength);
    auto& ptr = allocation_->ptr();

    // Figure out the buffer address
    const guest_ptr<void> BufferAddress = ptr + structure_size;

    // Create the string
    value_ = UNICODE_STRING::make_unique(kernel, ptr);
    value_->Length(value.length());
    value_->MaximumLength(MaximumLength);
    value_->BufferAddress(BufferAddress);

    value_->set(value);
}

} /* namespace inject */
} /* namespace introvirt */
