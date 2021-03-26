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
 * @see https://docs.microsoft.com/en-us/windows/win32/api/minwinbase/ns-minwinbase-overlapped
 */
class OVERLAPPED {
  public:
    virtual uint32_t Internal() const = 0;
    virtual void Internal(uint32_t Internal) = 0;

    virtual uint32_t InternalHigh() const = 0;
    virtual void InternalHigh(uint32_t InternalHigh) = 0;

    virtual uint32_t Offset() const = 0;
    virtual void Offset(uint32_t Offset) = 0;

    virtual uint32_t OffsetHigh() const = 0;
    virtual void OffsetHigh(uint32_t OffsetHigh) = 0;

    virtual guest_ptr<void> Pointer() const = 0;
    virtual void Pointer(const guest_ptr<void>& Pointer) = 0;

    virtual uint64_t hEvent() const = 0;
    virtual void hEvent(uint64_t hEvent) = 0;

    /**
     * @brief Create a OVERLAPPED
     */
    static std::shared_ptr<OVERLAPPED> make_shared(const guest_ptr<void>& ptr, bool x64);

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

    virtual ~OVERLAPPED() = default;
};

} // namespace ws2_32
} // namespace windows
} // namespace introvirt