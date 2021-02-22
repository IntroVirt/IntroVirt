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

#include <introvirt/core/event/Event.hh>

#include <memory>
#include <ostream>
#include <string>

namespace introvirt {

class GuestImpl;

/**
 * @brief Base interface for a Guest.
 *
 * A "guest" is the operating system running in a domain.
 *
 */
class Guest {
  public:
    /**
     * @brief Get the Guest OS type
     *
     * @return The Guest OS type
     */
    virtual OS os() const = 0;

    /**
     * @brief Check if the guest is 64-bit
     *
     * @return true if the guest is 64-bit
     * @return false if the guest is 32-bit
     */
    virtual bool x64() const = 0;

    /**
     * @brief Allocate a region of memory in the guest
     *
     * @param region_size The requested size of the region in bytes. May be rounded up.
     * @param executable Allow the region of memory to be executable
     * @return GuestVirtualAddress A pointer to the newly allocated region
     */
    virtual GuestVirtualAddress allocate(size_t& region_size, bool executable = false) = 0;

    /**
     * @brief Free a region of memory in the guest
     *
     * @param gva The base address to free
     * @param region_size The number of bytes to free
     */
    virtual void guest_free(GuestVirtualAddress& gva, size_t region_size) = 0;

    /**
     * @brief Used internally
     *
     * @return GuestImpl&
     */
    virtual GuestImpl& impl() = 0;
    virtual const GuestImpl& impl() const = 0;

    /**
     * @brief Destroy the instance
     */
    virtual ~Guest() = default;
};

} // namespace introvirt
