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

#include <introvirt/core/exception/MemoryException.hh>
#include <introvirt/core/fwd.hh>

#include <cstdint>

namespace introvirt {

/**
 * @brief Thrown when translating a guest virtual address is marked as not present
 *
 * This exception is thrown when we are unable to translate a guest virtual address into its
 * physical address.
 */
class VirtualAddressNotPresentException final : public MemoryException {
  public:
    /**
     * @brief Get the guest virtual address that was marked as not present
     *
     * @return The virtual address that failed to translate
     */
    uint64_t virtual_address() const;

    /**
     * @brief Get the page directory in use
     *
     * @return uint64_t
     */
    uint64_t page_directory() const;

    /**
     * @brief Construct a new Virtual Address Not Present Exception object
     *
     * @param virtual_address The virtual address that was not present
     * @param page_directory The paging directory that was used
     */
    VirtualAddressNotPresentException(uint64_t virtual_address, uint64_t page_directory);

    VirtualAddressNotPresentException(VirtualAddressNotPresentException&&) noexcept;
    VirtualAddressNotPresentException& operator=(VirtualAddressNotPresentException&&) noexcept;
    ~VirtualAddressNotPresentException() noexcept override;

  private:
    uint64_t virtual_address_;
    uint64_t page_directory_;
};

} // namespace introvirt
