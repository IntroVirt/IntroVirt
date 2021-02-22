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

#include <introvirt/core/fwd.hh>
#include <introvirt/core/memory/GuestMemoryMapping.hh>
#include <introvirt/util/json/json.hh>

#include <cstdint>
#include <ostream>
#include <string>

namespace introvirt {

/**
 * @brief Base class for both GuestAddress and GuestPhysicalAddress
 */
class GuestAddress {
  public:
    /**
     * @brief Returns the domain associated with this address
     *
     * @return Domain&
     */
    const Domain& domain() const { return *domain_; }

    /**
     * @brief Map the memory at this address
     *
     * @param length The number of bytes to map
     * @return A GuestMemoryMapping instance containing the mapped memory
     * @throws VirtualAddressNotPresentException if a virtual address is not present
     * @throws BadPhysicalAddressException if a pfn is not valid
     */
    virtual GuestMemoryMapping map(size_t length) const = 0;

    /**
     * @brief Get the physical address of the representation
     *
     * @return The physical address pointed to
     * @throws VirtualAddressNotPresentException if a virtual address is not present
     * @throws BadPhysicalAddressException if a pfn is not valid
     */
    virtual uint64_t physical_address() const = 0;

    /**
     * @brief Get the address' page number
     *
     * This performs ( value() >> PAGE_SHIFT ).
     *
     * @return The page number of the address
     */
    uint64_t page_number() const;

    /**
     * @brief Get the address' offset into the page
     *
     * This performs ( value() & ~PAGE_MASK ).
     *
     * @return The offset into the page
     */
    uint64_t page_offset() const HOT;

    /**
     * @brief Gets the address in whatever it's native representation is.
     *
     * GuestVirtualAddress will return a virtual address,
     * and GuestPhysicalAddress will return a physical address.
     *
     * @return The address in it's native representation
     */
    virtual uint64_t value() const = 0;

    /**
     * @brief Convert the address into a string representation
     *
     * @return The string representation of the address
     */
    virtual std::string to_string() const = 0;

    /**
     * @brief Create a copy of the GuestAddress
     *
     * @return std::unique_ptr<GuestAddress>
     */
    virtual std::unique_ptr<GuestAddress> clone() const = 0;

    /**
     * @brief Get a JSON representation of the address
     *
     * @return Json::Value
     */
    virtual Json::Value json() const;

    /**
     * @brief Offset the address
     *
     * @param offset The number of bytes to offset
     * @return The instance that was modified
     */
    virtual GuestAddress& operator+=(int offset) = 0;

    /**
     * @brief Offset the address
     *
     * @param offset The number of bytes to offset
     * @return The instance that was modified
     */
    virtual GuestAddress& operator+=(unsigned int offset) = 0;

    /**
     * @brief Offset the address
     *
     * @param offset The number of bytes to offset
     * @return The instance that was modified
     */
    virtual GuestAddress& operator+=(size_t offset) = 0;

    /**
     * @brief Offset the address
     *
     * @param offset The number of bytes to offset
     * @return The instance that was modified
     */
    virtual GuestAddress& operator+=(int64_t offset) = 0;

    /**
     * @brief Offset the address
     *
     * @param offset The number of bytes to offset
     * @return The instance that was modified
     */
    virtual GuestAddress& operator-=(int offset) = 0;

    /**
     * @brief Offset the address
     *
     * @param offset The number of bytes to offset
     * @return The instance that was modified
     */
    virtual GuestAddress& operator-=(unsigned int offset) = 0;

    /**
     * @brief Offset the address
     *
     * @param offset The number of bytes to offset
     * @return The instance that was modified
     */
    virtual GuestAddress& operator-=(size_t offset) = 0;

    /**
     * @brief Offset the address
     *
     * @param offset The number of bytes to offset
     * @return The instance that was modified
     */
    virtual GuestAddress& operator-=(int64_t offset) = 0;

    /**
     * @brief Destroy the instance
     */
    virtual ~GuestAddress() = default;

  protected:
    /**
     * @brief Construct a 'null' GuestAddress object
     */
    GuestAddress() : domain_(nullptr) {}

    /**
     * @brief Construct a new GuestAddress object
     *
     * @param domain The domain to which the address belongs
     */
    GuestAddress(const Domain& domain) : domain_(&domain) {}

    /**
     * @brief Copy constructor for GuestAddress
     */
    GuestAddress(const GuestAddress&) noexcept;

    /**
     * @brief Copy assignment operator for GuestAddress
     *
     * @return GuestAddress&
     */
    GuestAddress& operator=(const GuestAddress&) noexcept;

    /**
     * @brief Move constructor for GuestAddress
     */
    GuestAddress(GuestAddress&&) noexcept;

    /**
     * @brief Move assignment operator for GuestAddress
     *
     * @return GuestAddress&
     */
    GuestAddress& operator=(GuestAddress&&) noexcept;

  protected:
    const Domain* domain_;
};

/**
 * @brief Stream operator overload for GuestVirtualAddress
 *
 * @param os The stream to write to
 * @param guest_address The GuestAddress to write a string representation of
 * @return The stream that was provided
 */
std::ostream& operator<<(std::ostream& os, const GuestAddress& guest_address);

/**
 * @brief Convert the given GuestAddress to a string
 *
 * @param guest_address The address to convert into a string representation
 * @return The created string
 */
std::string to_string(const GuestAddress& guest_address);

} // namespace introvirt
