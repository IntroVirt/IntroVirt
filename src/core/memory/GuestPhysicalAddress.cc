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

#include <introvirt/core/domain/Domain.hh>
#include <introvirt/core/domain/Vcpu.hh>
#include <introvirt/core/memory/GuestPhysicalAddress.hh>

#include <sstream>

namespace introvirt {

GuestMemoryMapping GuestPhysicalAddress::map(size_t length) const {
    // Map the physical addresses directly
    // Calculate the number of pages required
    const uint64_t first_pfn = physical_address_ >> PageDirectory::PAGE_SHIFT;
    const uint64_t last_pfn = (physical_address_ + length) >> PageDirectory::PAGE_SHIFT;
    const int page_count = (last_pfn - first_pfn) + 1;

    uint64_t pfns[page_count];

    // Add all of the pages to our pfn_list
    uint64_t pfn = physical_address() >> PageDirectory::PAGE_SHIFT;
    for (int i = 0; i < page_count; ++i) {
        pfns[i] = pfn;
        ++pfn;
    }

    // Map and return
    return domain().map_pfns(pfns, page_count);
}

uint64_t GuestPhysicalAddress::physical_address() const { return physical_address_; }
uint64_t GuestPhysicalAddress::value() const { return physical_address(); }

template <typename I>
std::string n2hexstr(I w, size_t hex_len = sizeof(I) << 1) {
    static const char* digits = "0123456789ABCDEF";
    std::string rc(hex_len + 2, '0');
    rc[1] = 'x';

    for (size_t i = 0, j = (hex_len - 1) * 4; i < hex_len; ++i, j -= 4)
        rc[i + 2] = digits[(w >> j) & 0x0f];

    return rc;
}

std::string GuestPhysicalAddress::to_string() const { return n2hexstr(physical_address()); }

std::unique_ptr<GuestAddress> GuestPhysicalAddress::clone() const {
    return std::make_unique<GuestPhysicalAddress>(*this);
}

GuestPhysicalAddress::GuestPhysicalAddress(const GuestAddress& src) noexcept
    : GuestAddress(src), physical_address_(src.physical_address()) {}

GuestPhysicalAddress& GuestPhysicalAddress::operator=(const GuestAddress& src) noexcept {
    GuestAddress::operator=(src);
    physical_address_ = src.physical_address();
    return *this;
}

GuestPhysicalAddress& GuestPhysicalAddress::operator+=(int offset) {
    physical_address_ += offset;
    return *this;
}
GuestPhysicalAddress& GuestPhysicalAddress::operator+=(unsigned int offset) {
    physical_address_ += offset;
    return *this;
}
GuestPhysicalAddress& GuestPhysicalAddress::operator+=(size_t offset) {
    physical_address_ += offset;
    return *this;
}
GuestPhysicalAddress& GuestPhysicalAddress::operator+=(int64_t offset) {
    physical_address_ += offset;
    return *this;
}

GuestPhysicalAddress& GuestPhysicalAddress::operator-=(int offset) {
    physical_address_ -= offset;
    return *this;
}

GuestPhysicalAddress& GuestPhysicalAddress::operator-=(unsigned int offset) {
    physical_address_ -= offset;
    return *this;
}

GuestPhysicalAddress& GuestPhysicalAddress::operator-=(size_t offset) {
    physical_address_ -= offset;
    return *this;
}

GuestPhysicalAddress& GuestPhysicalAddress::operator-=(int64_t offset) {
    physical_address_ -= offset;
    return *this;
}

GuestPhysicalAddress::GuestPhysicalAddress(const GuestPhysicalAddress& src) noexcept = default;
GuestPhysicalAddress&
GuestPhysicalAddress::operator=(const GuestPhysicalAddress& src) noexcept = default;

GuestPhysicalAddress::GuestPhysicalAddress(GuestPhysicalAddress&&) noexcept = default;
GuestPhysicalAddress& GuestPhysicalAddress::operator=(GuestPhysicalAddress&&) noexcept = default;

} // namespace introvirt