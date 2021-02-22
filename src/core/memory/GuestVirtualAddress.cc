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
#include "core/event/EventImpl.hh"
#include <introvirt/core/event/ThreadLocalEvent.hh>

#include <introvirt/core/memory/GuestVirtualAddress.hh>

#include <introvirt/core/domain/Domain.hh>
#include <introvirt/core/domain/Vcpu.hh>
#include <introvirt/core/exception/MemoryException.hh>
#include <introvirt/core/exception/NullAddressException.hh>
#include <introvirt/core/memory/GuestPhysicalAddress.hh>
#include <introvirt/util/compiler.hh>

#include <log4cxx/logger.h>

#include <sstream>

namespace introvirt {

static log4cxx::LoggerPtr logger(log4cxx::Logger::getLogger("introvirt.GuestVirtualAddress"));

uint64_t GuestVirtualAddress::physical_address() const {
    if (physical_address_ != 0) {
        return physical_address_;
    }

    if (unlikely(page_directory_ == 0 || virtual_address_ == 0)) {
        throw NullAddressException();
    }

    // Cache it for the next call
    physical_address_ = domain().page_directory().translate(*this).physical_address();
    return physical_address_;
}

uint64_t GuestVirtualAddress::value() const { return virtual_address(); }

GuestMemoryMapping GuestVirtualAddress::map(size_t length) const {
    if (unlikely(page_directory_ == 0 || virtual_address_ == 0))
        throw NullAddressException();

    if (unlikely(length == 0))
        throw MemoryException("Tried to map 0 bytes");

    // Calculate the number of pages required
    const uint64_t first_vfn = virtual_address_ >> PageDirectory::PAGE_SHIFT;
    const uint64_t last_vfn = (virtual_address_ + length - 1) >> PageDirectory::PAGE_SHIFT;
    const int page_count = (last_vfn - first_vfn) + 1;

    // Most of the time it's only one page, so add a little short cut
    if (page_count == 1) {
        const uint64_t pa = physical_address();
        const uint64_t pfn = pa >> PageDirectory::PAGE_SHIFT;
        // Map and return
        return domain().map_pfns(&pfn, 1);
    }

    std::unique_ptr<uint64_t[]> pfns(new uint64_t[page_count]);
    uint64_t va = virtual_address();

    // Use ourselves for the first page
    {
        const uint64_t pa = physical_address();
        const uint64_t pfn = pa >> PageDirectory::PAGE_SHIFT;

        pfns[0] = pfn;

        va += PageDirectory::PAGE_SIZE;
        va &= 0xFFFFFFFFFFFFF000LL;
    }

    // Loop for the rest of the pages
    for (int i = 1; i < page_count; ++i) {
        const uint64_t pa = create(va).physical_address();
        const uint64_t pfn = pa >> PageDirectory::PAGE_SHIFT;

        pfns[i] = pfn;

        va += PageDirectory::PAGE_SIZE;
        va &= 0xFFFFFFFFFFFFF000LL;
    }

    // Map and return
    return domain().map_pfns(pfns.get(), page_count);
}

template <typename I>
std::string n2hexstr(I w, size_t hex_len = sizeof(I) << 1) {
    static const char* digits = "0123456789ABCDEF";
    std::string rc(hex_len + 2, '0');
    rc[1] = 'x';

    for (size_t i = 0, j = (hex_len - 1) * 4; i < hex_len; ++i, j -= 4)
        rc[i + 2] = digits[(w >> j) & 0x0f];

    return rc;
}

std::string GuestVirtualAddress::to_string() const { return n2hexstr(virtual_address()); }

GuestVirtualAddress GuestVirtualAddress::create(uint64_t virtual_address) const {
    if (unlikely(page_directory_ == 0))
        throw NullAddressException();

    GuestVirtualAddress result(domain(), virtual_address, page_directory_);

    if (physical_address_ && (virtual_address_ & PageDirectory::PAGE_MASK) ==
                                 (virtual_address & PageDirectory::PAGE_MASK)) {
        /*
         * If the new virtual address is on the same page, and if we have a physical address
         * already, we can just share the PFN with the new instance.
         */
        result.physical_address_ = (physical_address_ & PageDirectory::PAGE_MASK);
        result.physical_address_ |= (virtual_address & ~PageDirectory::PAGE_MASK);
    }
    return result;
}

GuestVirtualAddress::GuestVirtualAddress() {
    virtual_address_ = 0;
    physical_address_ = 0;
    page_directory_ = 0;
}

GuestVirtualAddress::GuestVirtualAddress(uint64_t virtual_address) {
    Event& event = ThreadLocalEvent::get();

    domain_ = &(event.domain());
    virtual_address_ = virtual_address;
    page_directory_ = event.impl().page_directory();
    physical_address_ = 0;
}

GuestVirtualAddress::GuestVirtualAddress(const Vcpu& vcpu, uint64_t virtual_address)
    : GuestAddress(vcpu.domain()) {

    if (ThreadLocalEvent::active()) {
        auto& event = ThreadLocalEvent::get();
        if (event.vcpu().id() == vcpu.id()) {
            page_directory_ = event.impl().page_directory();
        } else {
            page_directory_ = vcpu.registers().cr3();
        }
    } else {
        page_directory_ = vcpu.registers().cr3();
    }

    virtual_address_ = virtual_address;
    physical_address_ = 0;
}

GuestVirtualAddress::GuestVirtualAddress(const Domain& domain, uint64_t virtual_address,
                                         uint64_t page_directory)
    : GuestAddress(domain) {
    virtual_address_ = virtual_address;
    page_directory_ = page_directory;
    physical_address_ = 0;
}

GuestVirtualAddress GuestVirtualAddress::operator+(int offset) const {
    if (unlikely(page_directory_ == 0))
        throw NullAddressException();

    return create(virtual_address_ + offset);
}

GuestVirtualAddress GuestVirtualAddress::operator+(unsigned int offset) const {
    if (unlikely(page_directory_ == 0))
        throw NullAddressException();

    return create(virtual_address_ + offset);
}

GuestVirtualAddress GuestVirtualAddress::operator+(size_t offset) const {
    if (unlikely(page_directory_ == 0))
        throw NullAddressException();

    return create(virtual_address_ + offset);
}

GuestVirtualAddress GuestVirtualAddress::operator+(int64_t offset) const {
    if (unlikely(page_directory_ == 0))
        throw NullAddressException();

    return create(virtual_address_ + offset);
}

GuestVirtualAddress GuestVirtualAddress::operator-(int offset) const {
    if (unlikely(page_directory_ == 0))
        throw NullAddressException();

    return create(virtual_address_ - offset);
}

GuestVirtualAddress GuestVirtualAddress::operator-(unsigned int offset) const {
    if (unlikely(page_directory_ == 0))
        throw NullAddressException();

    return create(virtual_address_ - offset);
}

GuestVirtualAddress GuestVirtualAddress::operator-(size_t offset) const {
    if (unlikely(page_directory_ == 0))
        throw NullAddressException();

    return create(virtual_address_ - offset);
}

GuestVirtualAddress GuestVirtualAddress::operator-(int64_t offset) const {
    if (unlikely(page_directory_ == 0))
        throw NullAddressException();

    return create(virtual_address_ - offset);
}

GuestVirtualAddress& GuestVirtualAddress::operator+=(int offset) {
    if (unlikely(page_directory_ == 0))
        throw NullAddressException();

    const uint64_t new_virtual_address_ = virtual_address_ + offset;
    if (physical_address_ && ((virtual_address_ & PageDirectory::PAGE_MASK) !=
                              (new_virtual_address_ & PageDirectory::PAGE_MASK))) {
        physical_address_ = 0;
    } else if (physical_address_ != 0) {
        // Update the offset into the physical page
        physical_address_ &= x86::PageDirectory::PAGE_MASK;
        physical_address_ |= (new_virtual_address_ & ~x86::PageDirectory::PAGE_MASK);
    }
    virtual_address_ = new_virtual_address_;

    return *this;
}

GuestVirtualAddress& GuestVirtualAddress::operator+=(unsigned int offset) {
    if (unlikely(page_directory_ == 0))
        throw NullAddressException();

    const uint64_t new_virtual_address_ = virtual_address_ + offset;
    if (physical_address_ && ((virtual_address_ & PageDirectory::PAGE_MASK) !=
                              (new_virtual_address_ & PageDirectory::PAGE_MASK))) {
        physical_address_ = 0;
    } else if (physical_address_ != 0) {
        // Update the offset into the physical page
        physical_address_ &= x86::PageDirectory::PAGE_MASK;
        physical_address_ |= (new_virtual_address_ & ~x86::PageDirectory::PAGE_MASK);
    }
    virtual_address_ = new_virtual_address_;

    return *this;
}

GuestVirtualAddress& GuestVirtualAddress::operator+=(size_t offset) {
    if (unlikely(page_directory_ == 0))
        throw NullAddressException();

    const uint64_t new_virtual_address_ = virtual_address_ + offset;
    if (physical_address_ && ((virtual_address_ & PageDirectory::PAGE_MASK) !=
                              (new_virtual_address_ & PageDirectory::PAGE_MASK))) {
        physical_address_ = 0;
    } else if (physical_address_ != 0) {
        // Update the offset into the physical page
        physical_address_ &= x86::PageDirectory::PAGE_MASK;
        physical_address_ |= (new_virtual_address_ & ~x86::PageDirectory::PAGE_MASK);
    }
    virtual_address_ = new_virtual_address_;

    return *this;
}

GuestVirtualAddress& GuestVirtualAddress::operator+=(int64_t offset) {
    if (unlikely(page_directory_ == 0))
        throw NullAddressException();

    const uint64_t new_virtual_address_ = virtual_address_ + offset;
    if (physical_address_ && ((virtual_address_ & PageDirectory::PAGE_MASK) !=
                              (new_virtual_address_ & PageDirectory::PAGE_MASK))) {
        physical_address_ = 0;
    } else if (physical_address_ != 0) {
        // Update the offset into the physical page
        physical_address_ &= x86::PageDirectory::PAGE_MASK;
        physical_address_ |= (new_virtual_address_ & ~x86::PageDirectory::PAGE_MASK);
    }
    virtual_address_ = new_virtual_address_;

    return *this;
}

GuestVirtualAddress& GuestVirtualAddress::operator-=(int offset) {
    if (unlikely(page_directory_ == 0))
        throw NullAddressException();

    const uint64_t new_virtual_address_ = virtual_address_ - offset;
    if (physical_address_ && ((virtual_address_ & PageDirectory::PAGE_MASK) !=
                              (new_virtual_address_ & PageDirectory::PAGE_MASK))) {
        physical_address_ = 0;
    } else if (physical_address_ != 0) {
        // Update the offset into the physical page
        physical_address_ &= x86::PageDirectory::PAGE_MASK;
        physical_address_ |= (new_virtual_address_ & ~x86::PageDirectory::PAGE_MASK);
    }
    virtual_address_ = new_virtual_address_;

    return *this;
}

GuestVirtualAddress& GuestVirtualAddress::operator-=(unsigned int offset) {
    if (unlikely(page_directory_ == 0))
        throw NullAddressException();

    const uint64_t new_virtual_address_ = virtual_address_ - offset;
    if (physical_address_ && ((virtual_address_ & PageDirectory::PAGE_MASK) !=
                              (new_virtual_address_ & PageDirectory::PAGE_MASK))) {
        physical_address_ = 0;
    } else if (physical_address_ != 0) {
        // Update the offset into the physical page
        physical_address_ &= x86::PageDirectory::PAGE_MASK;
        physical_address_ |= (new_virtual_address_ & ~x86::PageDirectory::PAGE_MASK);
    }
    virtual_address_ = new_virtual_address_;

    return *this;
}

GuestVirtualAddress& GuestVirtualAddress::operator-=(size_t offset) {
    if (unlikely(page_directory_ == 0))
        throw NullAddressException();

    const uint64_t new_virtual_address_ = virtual_address_ - offset;
    if (physical_address_ && ((virtual_address_ & PageDirectory::PAGE_MASK) !=
                              (new_virtual_address_ & PageDirectory::PAGE_MASK))) {
        physical_address_ = 0;
    } else if (physical_address_ != 0) {
        // Update the offset into the physical page
        physical_address_ &= x86::PageDirectory::PAGE_MASK;
        physical_address_ |= (new_virtual_address_ & ~x86::PageDirectory::PAGE_MASK);
    }
    virtual_address_ = new_virtual_address_;

    return *this;
}

GuestVirtualAddress& GuestVirtualAddress::operator-=(int64_t offset) {
    if (unlikely(page_directory_ == 0))
        throw NullAddressException();

    const uint64_t new_virtual_address_ = virtual_address_ - offset;
    if (physical_address_ && ((virtual_address_ & PageDirectory::PAGE_MASK) !=
                              (new_virtual_address_ & PageDirectory::PAGE_MASK))) {
        physical_address_ = 0;
    } else if (physical_address_ != 0) {
        // Update the offset into the physical page
        physical_address_ &= x86::PageDirectory::PAGE_MASK;
        physical_address_ |= (new_virtual_address_ & ~x86::PageDirectory::PAGE_MASK);
    }
    virtual_address_ = new_virtual_address_;

    return *this;
}

int GuestVirtualAddress::operator-(const GuestVirtualAddress& src) const {
    return virtual_address() - src.virtual_address();
}
bool GuestVirtualAddress::operator>(const GuestVirtualAddress& src) const {
    return virtual_address() > src.virtual_address();
}
bool GuestVirtualAddress::operator>=(const GuestVirtualAddress& src) const {
    return virtual_address() >= src.virtual_address();
}
bool GuestVirtualAddress::operator<(const GuestVirtualAddress& src) const {
    return virtual_address() < src.virtual_address();
}
bool GuestVirtualAddress::operator<=(const GuestVirtualAddress& src) const {
    return virtual_address() <= src.virtual_address();
}
bool GuestVirtualAddress::operator==(const GuestVirtualAddress& src) const {
    return virtual_address() == src.virtual_address();
}
bool GuestVirtualAddress::operator!=(const GuestVirtualAddress& src) const {
    return virtual_address() != src.virtual_address();
}

GuestVirtualAddress::operator bool() const { return page_directory_ != 0 && virtual_address_ != 0; }
GuestVirtualAddress::operator uint64_t() const { return virtual_address_; }
GuestVirtualAddress::operator GuestPhysicalAddress() const {
    return GuestPhysicalAddress(domain(), physical_address());
}
GuestVirtualAddress::operator Json::Value() const { return virtual_address_; }

std::unique_ptr<GuestAddress> GuestVirtualAddress::clone() const {
    return std::make_unique<GuestVirtualAddress>(*this);
}

GuestVirtualAddress::GuestVirtualAddress(const GuestVirtualAddress& src) noexcept = default;
GuestVirtualAddress&
GuestVirtualAddress::operator=(const GuestVirtualAddress& src) noexcept = default;
GuestVirtualAddress::GuestVirtualAddress(GuestVirtualAddress&&) noexcept = default;
GuestVirtualAddress& GuestVirtualAddress::operator=(GuestVirtualAddress&&) noexcept = default;
GuestVirtualAddress::~GuestVirtualAddress() = default;

} // namespace introvirt