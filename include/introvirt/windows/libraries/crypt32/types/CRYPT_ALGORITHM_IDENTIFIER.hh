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

#include "CRYPTOAPI_BLOB.hh"

#include <introvirt/core/memory/GuestVirtualAddress.hh>

namespace introvirt {
namespace windows {
namespace crypt32 {

/**
 * @brief
 * @see
 * https://docs.microsoft.com/en-us/windows/win32/api/wincrypt/ns-wincrypt-crypt_algorithm_identifier
 */
class CRYPT_ALGORITHM_IDENTIFIER {
  public:
    virtual GuestVirtualAddress pszObjId() const = 0;
    virtual void pszObjId(const GuestVirtualAddress& gva) = 0;

    virtual const CRYPTOAPI_BLOB& Parameters() const = 0;
    virtual CRYPTOAPI_BLOB& Parameters() = 0;

    virtual std::string szObjId() const = 0;

    static std::unique_ptr<CRYPT_ALGORITHM_IDENTIFIER> make_unique(const GuestVirtualAddress& gva,
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

    virtual ~CRYPT_ALGORITHM_IDENTIFIER() = default;
};

} // namespace crypt32
} // namespace windows
} // namespace introvirt