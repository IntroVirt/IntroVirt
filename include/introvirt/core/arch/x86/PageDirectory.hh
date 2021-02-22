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

#ifdef __x86_64__

#include <introvirt/core/fwd.hh>

#include <introvirt/core/fwd.hh>
#include <introvirt/core/memory/GuestPhysicalAddress.hh>

#include <introvirt/util/compiler.hh>

#include <cstdint>
#include <memory>
#include <mutex>
#include <unordered_map>

namespace introvirt {
namespace x86 {

class PageDirectory final {
  public:
    /**
     * @brief
     *
     */
    static constexpr uint64_t PAGE_SHIFT = 12;

    /**
     * @brief The size of a physical page on x86
     */
    static constexpr uint64_t PAGE_SIZE = (1ull << PAGE_SHIFT);

    /**
     * @brief The mask used to get the page portion of an address
     */
    static constexpr uint64_t PAGE_MASK = (~(PAGE_SIZE - 1));

    /**
     * @brief Convert a GuestVirtualAddress to a GuestPhysicalAddress
     *
     * @param gva The virtual address to translate
     * @return The translated address
     * @throws VirtualAddressNotPresentException If the virtual address is not present
     */
    GuestPhysicalAddress translate(const GuestVirtualAddress& gva) const HOT;

    /**
     * @brief Reset the cached addresses
     */
    void reconfigure(const Vcpu& vcpu);

    /**
     * @brief Create a PageDirectory
     *
     * @param domain The domain this directory belongs to
     */
    PageDirectory(const Domain& domain);

    /**
     * @brief Destroy the instance
     */
    ~PageDirectory();

  private:
    const Domain& domain_;

    int pt_levels_ = 0;
    int pte_size_ = 0;
    uint64_t va_mask_ = 0;
    uint64_t mask_ = 0;
};

} // namespace x86

using PageDirectory = x86::PageDirectory;

} // namespace introvirt

#endif