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

#include <introvirt/core/memory/guest_ptr.hh>

#include <cstdint>
#include <memory>

namespace introvirt {
namespace windows {
namespace ws2_32 {

/**
 * @brief
 * @see https://docs.microsoft.com/en-us/windows/win32/api/winsock/ns-winsock-hostent
 */
class HOSTENT {
  public:
    // Direct structure members
    virtual guest_ptr<char[]> ph_name() const = 0;
    virtual void ph_name(const guest_ptr<char[]>& ptr) = 0;

    virtual guest_ptr<char*, guest_ptr_t> ph_aliases() const = 0;
    virtual void ph_aliases(const guest_ptr<char*, guest_ptr_t>& ptr) = 0;

    virtual uint16_t h_addrtype() const = 0;
    virtual void h_addrtype(uint16_t h_addrtype) = 0;

    virtual uint16_t h_length() const = 0;
    virtual void h_length(uint16_t h_length) = 0;

    virtual guest_ptr<uint8_t*, guest_ptr_t> ph_addr_list() const = 0;
    virtual void ph_addr_list(const guest_ptr<uint8_t*, guest_ptr_t>& ptr) = 0;

    // Helpers
    virtual std::vector<guest_ptr<char[]>> h_aliases() const = 0;

    /**
     * @brief Create a HOSTENT
     */
    static std::shared_ptr<HOSTENT> make_shared(const guest_ptr<void>& ptr, bool x64);

    /**
     * @brief Get the size of the structure
     * @param x64 If true, return the size of the 64-bit version, otherwise 32-bit
     */
    static size_t size(bool x64);

    /**
     * @brief Get the size of the structure
     * @param vcpu The VCPU to use as context
     *
     * This version will use the current processor state
     * to determine if the structure would be 32-bit or 64-bit.
     */
    static size_t size(const Vcpu& vcpu);

    virtual ~HOSTENT() = default;
};

} // namespace ws2_32
} // namespace windows
} // namespace introvirt