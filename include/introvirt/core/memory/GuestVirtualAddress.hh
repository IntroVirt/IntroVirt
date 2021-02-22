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

#include <introvirt/core/exception/NullAddressException.hh>
#include <introvirt/core/fwd.hh>
#include <introvirt/core/memory/GuestAddress.hh>
#include <introvirt/util/compiler.hh>
#include <introvirt/util/json/json.hh>

#include <cstdint>
#include <iostream>
#include <memory>

namespace introvirt {

/**
 * @brief Class to represents a guest virtual address
 *
 * To translate a virtual address into a mappable physical address,
 * the corresponding page directory is required. This class wraps
 * both together, representing a guest address.
 *
 */
class GuestVirtualAddress final : public GuestAddress {
  public:
    GuestMemoryMapping map(size_t length) const override HOT;

    uint64_t physical_address() const override HOT;

    /**
     * @brief Get the raw virtual address
     *
     * @return the raw virtual address
     */
    uint64_t virtual_address() const noexcept { return virtual_address_; }

    /**
     * @brief Get the page directory base for this virtual address
     *
     * @return The page directory base for this virtual address
     */
    uint64_t page_directory() const noexcept { return page_directory_; }

    /**
     * @brief Set the page directory base for this virtual address
     *
     * @param page_directory The page directory base for this virtual address
     */
    void page_directory(uint64_t page_directory) noexcept {
        if (page_directory != page_directory_) {
            page_directory_ = page_directory;
            physical_address_ = 0;
        }
    }

    /**
     * @copydoc GuestAddress::value()
     *
     * This version will return a virtual address
     */
    uint64_t value() const override;

    std::string to_string() const override;

    /**
     * @brief Create a new GuestVirtualAddress using the same Vcpu as the original
     *
     * @param virtual_address The virtual address to use
     * @return A GuestVirtualAddress using the same Vcpu as the callee
     */
    GuestVirtualAddress create(uint64_t virtual_address) const;

    /**
     * @brief Construct a 'null' GuestVirtualAddress
     */
    GuestVirtualAddress();

    /**
     * @brief Construct a new GuestVirtualAddress
     *
     * This version relies on the current active event.
     * The GuestVirtualAddress will be initialized with the currently active domain.
     * The page directory will be set to the value in the current event's page_directory().
     *
     * @param gva The virtual address to wrap
     */
    GuestVirtualAddress(uint64_t virtual_address);

    /**
     * @brief Construct a new GuestVirtualAddress
     *
     * If in an event, the page directory will be set to the value in the current event's
     * page_directory(). If not, the CR3 value will be used from the Vcpu.
     *
     * @param gva The virtual address to wrap
     */
    GuestVirtualAddress(const Vcpu& vcpu, uint64_t virtual_address);

    /**
     * @brief Construct a new GuestVirtualAddress
     *
     * @param domain The VCPU to use for context
     * @param gva The virtual address to wrap
     * @param page_directory The page directory base to use for address translation
     */
    GuestVirtualAddress(const Domain& domain, uint64_t virtual_address, uint64_t page_directory);

    /**
     * @brief Copy constructor for GuestVirtualAddress
     */
    GuestVirtualAddress(const GuestVirtualAddress&) noexcept;

    /**
     * @brief Copy assignment operator for GuestVirtualAddress
     *
     * @return GuestVirtualAddress&
     */
    GuestVirtualAddress& operator=(const GuestVirtualAddress&) noexcept;

    /**
     * @brief Move constructor for GuestVirtualAddress
     */
    GuestVirtualAddress(GuestVirtualAddress&&) noexcept;

    /**
     * @brief Move assignment operator for GuestVirtualAddress
     *
     * @return GuestVirtualAddress&
     */
    GuestVirtualAddress& operator=(GuestVirtualAddress&&) noexcept;

    /**
     * @brief Get the difference between the two addresses
     *
     * @param The value to subtract
     * @return The number of bytes between the two addresses
     */
    int operator-(const GuestVirtualAddress& src) const;

    /**
     * @brief Add to the offset and return a new GuestVirtualAddress
     *
     * @param offset The number of bytes to offset
     * @return A GuestVirtualAddress offset from the original
     */
    GuestVirtualAddress operator+(int offset) const;

    /**
     * @brief Add to the offset and return a new GuestVirtualAddress
     *
     * @param offset The number of bytes to offset
     * @return A GuestVirtualAddress offset from the original
     */
    GuestVirtualAddress operator+(unsigned int offset) const;

    /**
     * @brief Add to the offset and return a new GuestVirtualAddress
     *
     * @param offset The number of bytes to offset
     * @return A GuestVirtualAddress offset from the original
     */
    GuestVirtualAddress operator+(size_t offset) const;

    /**
     * @brief Add to the offset and return a new GuestVirtualAddress
     *
     * @param offset The number of bytes to offset
     * @return A GuestVirtualAddress offset from the original
     */
    GuestVirtualAddress operator+(int64_t offset) const;

    /**
     * @brief Add to the offset and return a new GuestVirtualAddress
     *
     * @param offset The number of bytes to offset
     * @return A GuestVirtualAddress offset from the original
     */
    GuestVirtualAddress operator-(int offset) const;

    /**
     * @brief Add to the offset and return a new GuestVirtualAddress
     *
     * @param offset The number of bytes to offset
     * @return A GuestVirtualAddress offset from the original
     */
    GuestVirtualAddress operator-(unsigned int offset) const;

    /**
     * @brief Add to the offset and return a new GuestVirtualAddress
     *
     * @param offset The number of bytes to offset
     * @return A GuestVirtualAddress offset from the original
     */
    GuestVirtualAddress operator-(size_t offset) const;

    /**
     * @brief Add to the offset and return a new GuestVirtualAddress
     *
     * @param offset The number of bytes to offset
     * @return A GuestVirtualAddress offset from the original
     */
    GuestVirtualAddress operator-(int64_t offset) const;

    /**
     * @brief Offset the virtual address
     *
     * @param offset The number of bytes to offset
     * @return The instance that was modified
     */
    GuestVirtualAddress& operator+=(int offset) override;

    /**
     * @brief Offset the virtual address
     *
     * @param offset The number of bytes to offset
     * @return The instance that was modified
     */
    GuestVirtualAddress& operator+=(unsigned int offset) override;

    /**
     * @brief Offset the virtual address
     *
     * @param offset The number of bytes to offset
     * @return The instance that was modified
     */
    GuestVirtualAddress& operator+=(size_t offset) override;

    /**
     * @brief Offset the virtual address
     *
     * @param offset The number of bytes to offset
     * @return The instance that was modified
     */
    GuestVirtualAddress& operator+=(int64_t offset) override;

    /**
     * @brief Offset the virtual address
     *
     * @param offset The number of bytes to offset
     * @return The instance that was modified
     */
    GuestVirtualAddress& operator-=(int offset) override;

    /**
     * @brief Offset the virtual address
     *
     * @param offset The number of bytes to offset
     * @return The instance that was modified
     */
    GuestVirtualAddress& operator-=(unsigned int offset) override;

    /**
     * @brief Offset the virtual address
     *
     * @param offset The number of bytes to offset
     * @return The instance that was modified
     */
    GuestVirtualAddress& operator-=(size_t offset) override;

    /**
     * @brief Offset the virtual address
     *
     * @param offset The number of bytes to offset
     * @return The instance that was modified
     */
    GuestVirtualAddress& operator-=(int64_t offset) override;

    /**
     * @brief Greater-than comparison operator
     */
    bool operator>(const GuestVirtualAddress&) const;

    /**
     * @brief Greater-or-equal than comparison operator
     */
    bool operator>=(const GuestVirtualAddress&) const;

    /**
     * @brief Less-than comparison operator
     */
    bool operator<(const GuestVirtualAddress&) const;

    /**
     * @brief Less-or-equal than comparison operator
     */
    bool operator<=(const GuestVirtualAddress&) const;

    /**
     * @brief Equal comparison operator
     */
    bool operator==(const GuestVirtualAddress&) const;

    /**
     * @brief Not equal comparison operator
     */
    bool operator!=(const GuestVirtualAddress&) const;

    /**
     * @brief Bool operator overload
     *
     * @return true if the GuestVirtualAddress is not null
     * @return false if the GuestVirtualAddress is null
     */
    explicit operator bool() const;

    /**
     * @brief uint64_t operator overload
     */
    explicit operator uint64_t() const;

    /**
     * @brief GuestPhysicalAddress operator overload
     */
    explicit operator GuestPhysicalAddress() const;

    /**
     * @brief Get the address in json format
     *
     * @return Json::Value
     */
    operator Json::Value() const;

    std::unique_ptr<GuestAddress> clone() const override;

    /**
     * @brief Destroy the instance
     */
    ~GuestVirtualAddress() override;

  private:
    uint64_t virtual_address_;
    uint64_t page_directory_;
    mutable uint64_t physical_address_;
};

inline GuestVirtualAddress NullGuestAddress() { return GuestVirtualAddress(); }

} // namespace introvirt