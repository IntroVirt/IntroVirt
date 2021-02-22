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
#include <introvirt/windows/libraries/crypt32/types/types.hh>

#include <cstdint>

namespace introvirt {
namespace windows {
namespace crypt32 {

/**
 * @brief
 *
 * @see
 * https://docs.microsoft.com/en-us/windows/win32/api/wincrypt/ns-wincrypt-cert_strong_sign_para
 */
class CERT_STRONG_SIGN_PARA {
  public:
    virtual uint32_t cbSize() const = 0;
    virtual void cbSize(uint32_t cbSize) = 0;

    virtual uint32_t dwInfoChoice() const = 0;
    virtual void dwInfoChoice(uint32_t dwInfoChoice) = 0;

    virtual GuestVirtualAddress pvInfo() const = 0;
    virtual void pvInfo(const GuestVirtualAddress& gva) = 0;

    virtual GuestVirtualAddress pSerializedInfo() const = 0;
    virtual void pSerializedInfo(const GuestVirtualAddress& gva) = 0;

    virtual GuestVirtualAddress pszOID() const = 0;
    virtual void pszOID(const GuestVirtualAddress& gva) = 0;

    static std::unique_ptr<CERT_STRONG_SIGN_PARA> make_unique(const GuestVirtualAddress& gva,
                                                              bool x64);

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

    virtual ~CERT_STRONG_SIGN_PARA() = default;
};

} // namespace crypt32
} // namespace windows
} // namespace introvirt