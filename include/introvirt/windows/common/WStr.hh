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

#include "Utf16String.hh"

#include <introvirt/core/memory/guest_ptr.hh>
#include <introvirt/fwd.hh>

#include <cstdint>
#include <memory>

namespace introvirt {
namespace windows {

/**
 * @brief Basic raw UTF-16 string wrapper
 */
class WStr : public Utf16String {

  public:
    /**
     * @returns The length of the string, in bytes
     */
    uint16_t Length() const override;

    /**
     * @returns The maximum number of bytes we can fit in the buffer
     */
    uint16_t MaximumLength() const;

    /**
     * @returns The raw UTF16LE buffer
     */
    const uint8_t* Buffer() const override;

    /**
     * @brief Update the buffer with a new value
     */
    void set(const std::u16string& value) override;
    using Utf16String::set;

    /**
     * @brief Get the address of the buffer in the guest
     */
    GuestVirtualAddress address() const;

    /**
     * @brief Parse a UTF16LE string from guest memory
     *
     * This version attemps to automatically determine the size of the string
     *
     * @param gva The virtual address of the string.
     */
    WStr(const GuestVirtualAddress& gva);

    /**
     * @brief Parse a UTF16LE string from guest memory
     *
     * This version attemps to automatically determine the size of the string
     *
     * @param gva The virtual address of the string.
     * @param buffer_size The maximum size of the buffer
     */
    WStr(const GuestVirtualAddress& gva, size_t buffer_size);

    /**
     * @brief Parse a UTF16LE string from guest memory
     *
     * This version explicitly sets the size of the string
     *
     * @param gva The virtual address of the string.
     * @param len The length of the string in bytes
     * @param buffer_size The size to map, or 0 to use the size of the string
     */
    WStr(const GuestVirtualAddress& gva, size_t len, size_t buffer_size);

    /*
     * Create a UTF16LE string from already-mapped guest memory
     * @param len The length of the string in bytes
     */
    WStr(guest_ptr<uint8_t[]>&& buffer, size_t len = 0);

    WStr(WStr&&) noexcept;
    WStr& operator=(WStr&&) noexcept;
    ~WStr() override;

  private:
    class IMPL;
    std::unique_ptr<IMPL> pImpl_;
};

} /* namespace windows */
} /* namespace introvirt */
