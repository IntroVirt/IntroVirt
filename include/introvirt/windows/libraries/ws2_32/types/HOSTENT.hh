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

#include <introvirt/core/memory/GuestVirtualAddress.hh>

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
    virtual GuestVirtualAddress ph_name() const = 0;
    virtual void ph_name(const GuestVirtualAddress& gva) = 0;

    virtual GuestVirtualAddress ph_aliases() const = 0;
    virtual void ph_aliases(const GuestVirtualAddress& gva) = 0;

    virtual uint16_t h_addrtype() const = 0;
    virtual void h_addrtype(uint16_t h_addrtype) = 0;

    virtual uint16_t h_length() const = 0;
    virtual void h_length(uint16_t h_length) = 0;

    virtual GuestVirtualAddress ph_addr_list() const = 0;
    virtual void ph_addr_list(const GuestVirtualAddress& gva) = 0;

    // Helpers
    virtual std::string h_name() const = 0;
    virtual std::vector<std::string> h_aliases() const = 0;

    /**
     * @brief Create a WSADATA
     */
    static std::unique_ptr<HOSTENT> make_unique(const GuestVirtualAddress& gva, bool x64);

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