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

namespace introvirt {
namespace windows {
namespace secur32 {

/**
 * @brief
 *
 * @see https://docs.microsoft.com/en-us/windows/win32/api/sspi/ns-sspi-secbufferdesc
 */
class SecBufferDesc {
  public:
    virtual uint32_t ulVersion() const = 0;
    virtual void ulVersion(uint32_t ulVersion) = 0;

    virtual uint32_t cBuffers() const = 0;
    virtual void cBuffers(uint32_t cBuffers) = 0;

    virtual GuestVirtualAddress pBuffers() const = 0;
    virtual void pBuffers(const GuestVirtualAddress& gva) = 0;

    /**
     * @brief Create a SecBufferDesc
     */
    static std::unique_ptr<SecBufferDesc> make_unique(const GuestVirtualAddress& gva, bool x64);

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

    virtual ~SecBufferDesc() = default;
};

} // namespace secur32
} // namespace windows
} // namespace introvirt