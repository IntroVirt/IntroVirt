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
 *
 * @see https://docs.microsoft.com/en-us/windows/win32/api/ws2def/ns-ws2def-wsabuf
 */
class WSABUF {
  public:
    /**
     * @brief Get the length of the buffer, in bytes
     */
    virtual uint32_t len() const = 0;

    /**
     * @brief Set the length of the buffer, in bytes
     */
    virtual void len(uint32_t len) = 0;

    /**
     * @brief Get the buffer
     */
    virtual guest_ptr<const uint8_t[]> buf() const = 0;
    virtual guest_ptr<uint8_t[]> buf() = 0;

    /**
     * @brief Set the buffer
     */
    virtual void buf(const guest_ptr<uint8_t[]>& buf) = 0;

    /**
     * @brief Parse a WSABUF instance from the guest
     *
     * @param ptr The address of the instance
     * @param x64 If the structure is 64-bit or not
     * @return std::shared_ptr<WSABUF>
     */
    static std::shared_ptr<WSABUF> make_shared(const guest_ptr<void>& ptr, bool x64);

    /**
     * @brief Get the size of the structure
     */
    static size_t size(bool x64);
};

} // namespace ws2_32
} // namespace windows
} // namespace introvirt
