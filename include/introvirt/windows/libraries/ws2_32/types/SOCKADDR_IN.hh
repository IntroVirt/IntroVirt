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

#include "SOCKADDR.hh"

namespace introvirt {
namespace windows {
namespace ws2_32 {

/**
 * @brief
 * @see https://docs.microsoft.com/en-us/windows/win32/winsock/sockaddr-2
 */
class SOCKADDR_IN : public SOCKADDR {
  public:
    /**
     * @brief Get the port.
     *
     * Endianness is already handled.
     *
     * @return uint16_t
     */
    virtual uint16_t sin_port() const = 0;
    virtual void sin_port(uint16_t sin_port) = 0;

    /**
     * @brief Get the address.
     *
     * @return std::array<uint8_t, 4>
     */
    virtual std::array<uint8_t, 4> sin_addr() const = 0;
    virtual void sin_addr(const std::array<uint8_t, 4>& sin_addr) = 0;

    // Helper functions
    /**
     * @brief Get the IP address as a string
     */
    virtual std::string inet_ntoa() const = 0;

    virtual ~SOCKADDR_IN() = default;
};

} // namespace ws2_32
} // namespace windows
} // namespace introvirt