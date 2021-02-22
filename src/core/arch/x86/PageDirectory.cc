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
#include "core/domain/DomainImpl.hh"
#include "core/domain/GuestImpl.hh"
#include "core/domain/VcpuImpl.hh"

#include <introvirt/core/arch/x86/PageDirectory.hh>
#include <introvirt/core/arch/x86/Registers.hh>
#include <introvirt/core/exception/VirtualAddressNotPresentException.hh>
#include <introvirt/core/memory/GuestVirtualAddress.hh>
#include <introvirt/core/memory/guest_ptr.hh>

#include <log4cxx/logger.h>

#include <iostream>

namespace introvirt {
namespace x86 {

static log4cxx::LoggerPtr logger(log4cxx::Logger::getLogger("introvirt.arch.x86.PageDirectory"));

class PageTableEntry {
  public:
    /**
     * @brief Check if the page table entry is marked as present
     *
     * @return true if the page table entry is present
     * @return false if the page table entry is not present
     */
    bool present() const { return value_ & (1 << 0); }

    /**
     * @brief Check if the page is marked as writable
     *
     * @return true if the page is writable
     * @return false if the page is not writable
     */
    bool writable() const { return value_ & (1 << 1); }

    /**
     * @brief Check if the page is accessible from userland
     *
     * @return true If the page can be accessed from userland
     * @return false If the page is marked as kernel-only
     */
    bool user() const { return value_ & (1 << 2); }

    /**
     * @brief Check if write-through caching is enabled
     *
     * @return true if the page is marked as write-through
     * @return false if the page is in write-back mode
     */
    bool write_through() const { return value_ & (1 << 3); }

    /**
     * @brief Check if the cache is disable for this page
     *
     * @return true if the cache is disabled
     * @return false if the cache is not disabled
     */
    bool cache_disabled() const { return value_ & (1 << 4); }

    /**
     * @brief Check if the acccessed bit is set
     *
     * The accessed bit is set each time the page is accessed.
     * It can be cleared by the OS and used however the OS wants.
     *
     * @return true if the page has been accessed since the last time the bit was cleared
     * @return false if the page has not been accessed since the last time the bit was cleared
     */
    bool accessed() const { return value_ & (1 << 5); }

    /**
     * @brief Check if the dirty bit is set
     *
     * @return true if the page has been written to since the last time the bit was cleared
     * @return false if the page has not been written to since the last time the bit was cleared
     */
    bool dirty() const { return value_ & (1 << 6); }

    /**
     * @brief Check if the huge bit is setkcal
     *
     * Invalid for levels 1 and 4.
     *
     * On level 3, this indicates a 1GiB page.
     * On level 2, this indicates a 2MiB page.
     *
     * @return true
     * @return false
     */
    bool huge() const { return value_ & (1 << 7); }

    /**
     * @brief Check if the global bit is set
     *
     * If this bit is set, the page is not flushed from caches when CR3 switches.
     * Requires CR4.PGE to be set.
     *
     * @return true if the page is marked as global
     * @return false if the page is not marked as global
     */
    bool global() const { return value_ & (1 << 8); }

    /**
     * @brief Get the three OS-useable bits
     *
     * Bits 9-11 of the page table entry are free for the OS to use
     *
     * @return The OS-useable bits
     */
    int available1() const { return (value_ >> 9) & 0x7; }

    /**
     * @brief Get the physical address
     *
     * @return GuestPhysicalAddress
     */
    uint64_t physical_address() const { return value_ & 0xFFFFFFFFF000; }

    /**
     * @brief Get the 11 OS-useable bits
     *
     * Bits 52-62 of the page table entry are free for the OS to use
     *
     * @return The OS-useable bits
     */
    int available2() const { return (value_ >> 52) & 0x7FF; }

    /**
     * @brief Get the N/X bit
     *
     * This is used if the NXE bit is set in the EFER MSR
     *
     * @return true if the page is marked as no-execute
     * @return false if the page is executable
     */
    bool no_execute() const { return value_ & (1ull << 63); }

    /**
     * @brief Construct a new Page Table Entry object
     *
     * @param value The value of the page table entry
     */
    PageTableEntry(uint64_t value) : value_(value) {}

  private:
    uint64_t value_;
};

GuestPhysicalAddress PageDirectory::translate(const GuestVirtualAddress& gva) const {

retry:
    uint64_t virt = gva.virtual_address() & va_mask_;
    uint64_t paddr = gva.page_directory() & ((pt_levels_ == 3) ? 0xFFFFFFE0 : 0x7FFFFFFFFFFFF000LL);
    uint64_t mask = mask_;

    PageTableEntry pte(0);

    /*
     *  Walk the page tables
     */
    for (int level = pt_levels_; level > 0; level--) {
        // Offset to the correct PTE
        paddr += ((virt & mask) >> (__builtin_ffsll(mask) - 1)) * pte_size_;

        // Read in the PTE
        uint64_t pte_val = 0;
        GuestPhysicalAddress pte_addr(domain_, paddr);
        if (pte_size_ == 8) {
            pte_val = *guest_ptr<uint64_t>(pte_addr);
        } else {
            pte_val = *guest_ptr<uint32_t>(pte_addr);
        }

        pte = PageTableEntry(pte_val);
        if (unlikely(pte.present() == false)) {
            if (likely(domain_.guest() != nullptr)) {
                // Let the guest handler give it a try
                switch (domain_.guest()->impl().handle_page_fault(gva, pte_val)) {
                case GuestPageFaultResult::PTE_FIXED:
                    pte = PageTableEntry(pte_val);
                    break;
                case GuestPageFaultResult::RETRY:
                    goto retry;
                case GuestPageFaultResult::FAILURE:
                    throw VirtualAddressNotPresentException(gva);
                }
            } else {
                throw VirtualAddressNotPresentException(gva);
            }
        }

        // Read the address provided in the PTE
        paddr = pte.physical_address();

        if (pte.huge()) {
            if ((level == 2 || (level == 3 && pt_levels_ == 4))) {
                mask = ((mask ^ ~-mask) >> 1); /* All bits below first set bit */

                GuestPhysicalAddress result(domain_, ((paddr & ~mask) | (virt & mask)));
                return result;
            }
        }

        mask >>= (pt_levels_ == 2 ? 10 : 9);
    }

    // Done
    GuestPhysicalAddress result(domain_, (paddr & PAGE_MASK) | (virt & ~PAGE_MASK));
    return result;
}

void PageDirectory::reconfigure(const Vcpu& vcpu) {
    const Registers& regs = vcpu.registers();
    if (regs.efer().lma()) {
        pt_levels_ = 4;
    } else if (regs.cr4().pae()) {
        pt_levels_ = 3;
    } else {
        pt_levels_ = 2;
    }

    switch (pt_levels_) {
    case 4:
        va_mask_ = 0x0000ffffffffffffull;
        mask_ = 0x0000ff8000000000ull;
        pte_size_ = 8;
        break;
    case 3:
        va_mask_ = 0x00000000ffffffffull;
        mask_ = 0x0000007fc0000000ull;
        pte_size_ = 8;
        break;
    default:
        va_mask_ = 0x00000000ffffffffull;
        mask_ = 0x00000000ffc00000ull;
        pte_size_ = 4;
        break;
    }
}

PageDirectory::PageDirectory(const Domain& domain) : domain_(domain) {}

PageDirectory::~PageDirectory() = default;

} // namespace x86
} // namespace introvirt