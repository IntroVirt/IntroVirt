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

#include <introvirt/core/arch/arch.hh>
#include <introvirt/core/domain/Domain.hh>
#include <introvirt/core/memory/GuestAddress.hh>

#include <boost/io/ios_state.hpp>

namespace introvirt {

uint64_t GuestAddress::page_number() const { return value() >> PageDirectory::PAGE_SHIFT; }
uint64_t GuestAddress::page_offset() const { return value() & ~PageDirectory::PAGE_MASK; }

// Copying
GuestAddress::GuestAddress(const GuestAddress& src) noexcept = default;
GuestAddress& GuestAddress::operator=(const GuestAddress& src) noexcept = default;

// Moving
GuestAddress::GuestAddress(GuestAddress&&) noexcept = default;
GuestAddress& GuestAddress::operator=(GuestAddress&&) noexcept = default;

Json::Value GuestAddress::json() const { return value(); }

std::ostream& operator<<(std::ostream& os, const GuestAddress& guest_address) {
    os << guest_address.to_string();
    return os;
}

std::string to_string(const GuestAddress& guest_address) { return guest_address.to_string(); }

} // namespace introvirt