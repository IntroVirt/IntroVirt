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

#include <introvirt/util/compiler.hh>

#include <cstdint>

namespace introvirt {

/**
 * @brief A mapping of guest memory
 *
 * A wrapper class to hold a mapping of guest memory.
 * Generally you would use a guest_ptr instead of directly using this class.
 *
 * Keep in mind that since we have to map entire pages of memory, you will have to offset into the
 * buffer returned by get().
 *
 */
class GuestMemoryMapping final {
  public:
    /**
     * @brief Get the raw memory mapping
     *
     * @return The raw memory mapping
     */
    void* get() { return mapping_; }

    /**
     * @brief Get the raw memory mapping
     *
     * @return A const version of the raw memory mapping
     */
    const void* get() const { return mapping_; }

    /**
     * @brief Returns the number of bytes that are mapped
     *
     * @return unsigned int
     */
    unsigned int length() const { return length_; }

    /**
     * @brief Construct a "null" GuestMemoryMapping
     */
    GuestMemoryMapping() : mapping_(nullptr), length_(0) {}

    /**
     * @brief Construct a GuestMemoryMapping
     *
     * @param mapping The mapped guest memory
     * @param length The number of bytes that have been mapped
     */
    GuestMemoryMapping(void* mapping, unsigned int length) : mapping_(mapping), length_(length) {}

    /**
     * @brief Copy constructor
     */
    GuestMemoryMapping(const GuestMemoryMapping&) = delete;

    /**
     * @brief Copy assignment operator
     */
    GuestMemoryMapping& operator=(const GuestMemoryMapping&) = delete;

    /**
     * @brief Move constructor
     */
    GuestMemoryMapping(GuestMemoryMapping&&) noexcept;

    /**
     * @brief Move assignment operator
     */
    GuestMemoryMapping& operator=(GuestMemoryMapping&&) noexcept HOT;

    /**
     * @brief Destroy the instance
     * The memory will be unmapped
     */
    ~GuestMemoryMapping() HOT;

  private:
    void* mapping_;
    std::size_t length_;
};

} // namespace introvirt