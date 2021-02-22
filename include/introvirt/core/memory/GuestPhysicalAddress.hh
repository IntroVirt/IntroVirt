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
#include <introvirt/core/memory/GuestAddress.hh>
#include <introvirt/util/compiler.hh>

#include <cstdint>

namespace introvirt {

/**
 * @brief Represents a physical address inside of a physical machine
 *
 */
class GuestPhysicalAddress final : public GuestAddress {
  public:
    GuestMemoryMapping map(size_t length) const override HOT;

    /**
     * @copydoc GuestAddress::physical_address()
     *
     * The implementation in GuestPhysicalAddress just returns a value,
     * and will not throw an exception.
     */
    uint64_t physical_address() const override;

    /**
     * @copydoc GuestAddress::value()
     *
     * This version will return a physical address
     */
    uint64_t value() const override HOT;

    std::string to_string() const override;

    /**
     * @brief Construct a new GuestPhysicalAddress
     *
     * @param domain The domain to which the address belongs
     * @param physical_address The physical address in guest memory
     */
    GuestPhysicalAddress(const Domain& domain, uint64_t physical_address)
        : GuestAddress(domain), physical_address_(physical_address) {}

    /**
     * @brief Copy constructor
     */
    GuestPhysicalAddress(const GuestAddress&) noexcept;

    /**
     * @brief Copy assignment operator
     */
    GuestPhysicalAddress& operator=(const GuestAddress&) noexcept;

    /**
     * @brief Copy constructor
     */
    GuestPhysicalAddress(const GuestPhysicalAddress&) noexcept;

    /**
     * @brief Copy assignment operator
     */
    GuestPhysicalAddress& operator=(const GuestPhysicalAddress&) noexcept;

    /**
     * @brief Move constructor
     */
    GuestPhysicalAddress(GuestPhysicalAddress&&) noexcept;

    /**
     * @brief Move assignment operator
     */
    GuestPhysicalAddress& operator=(GuestPhysicalAddress&&) noexcept;

    std::unique_ptr<GuestAddress> clone() const override;

    /**
     * @brief Offset the physical address
     *
     * @param offset The number of bytes to offset
     * @return The instance that was modified
     */
    GuestPhysicalAddress& operator+=(int offset) override;

    /**
     * @brief Offset the physical address
     *
     * @param offset The number of bytes to offset
     * @return The instance that was modified
     */
    GuestPhysicalAddress& operator+=(unsigned int offset) override;

    /**
     * @brief Offset the physical address
     *
     * @param offset The number of bytes to offset
     * @return The instance that was modified
     */
    GuestPhysicalAddress& operator+=(size_t offset) override;

    /**
     * @brief Offset the physical address
     *
     * @param offset The number of bytes to offset
     * @return The instance that was modified
     */
    GuestPhysicalAddress& operator+=(int64_t offset) override;

    /**
     * @brief Offset the physical address
     *
     * @param offset The number of bytes to offset
     * @return The instance that was modified
     */
    GuestPhysicalAddress& operator-=(int offset) override;

    /**
     * @brief Offset the physical address
     *
     * @param offset The number of bytes to offset
     * @return The instance that was modified
     */
    GuestPhysicalAddress& operator-=(unsigned int offset) override;

    /**
     * @brief Offset the physical address
     *
     * @param offset The number of bytes to offset
     * @return The instance that was modified
     */
    GuestPhysicalAddress& operator-=(size_t offset) override;

    /**
     * @brief Offset the physical address
     *
     * @param offset The number of bytes to offset
     * @return The instance that was modified
     */
    GuestPhysicalAddress& operator-=(int64_t offset) override;

    /**
     * @brief Destructor
     */
    ~GuestPhysicalAddress() override = default;

  private:
    uint64_t physical_address_;
};

} // namespace introvirt