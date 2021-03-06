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
namespace secur32 {

/**
 * @brief
 *
 * @see https://docs.microsoft.com/en-us/windows/win32/api/sspi/ns-sspi-secbuffer
 */
class SecBuffer {
  public:
    virtual uint32_t cbBuffer() const = 0;
    virtual void cbBuffer(uint32_t value) = 0;

    virtual uint32_t BufferType() const = 0;
    virtual void BufferType(uint32_t value) = 0;

    virtual guest_ptr<uint8_t[]> pvBuffer() const = 0;
    virtual void pvBuffer(const guest_ptr<uint8_t[]>& ptr) = 0;

    static std::shared_ptr<SecBuffer> make_shared(const guest_ptr<void>& ptr, bool x64);

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
};

} // namespace secur32
} // namespace windows
} // namespace introvirt