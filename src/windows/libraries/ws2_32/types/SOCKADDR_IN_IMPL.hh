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
#include <introvirt/windows/libraries/ws2_32/types/SOCKADDR_IN.hh>

#include <algorithm>
#include <arpa/inet.h>

namespace introvirt {
namespace windows {
namespace ws2_32 {

namespace structs {

struct _SOCKADDR_IN {
    uint16_t sa_family;
    union {
        struct {
            uint16_t sin_port;
            uint8_t sin_addr[4];
        };
        uint8_t sa_data[14];
    };
};

}; // namespace structs

class SOCKADDR_IN_IMPL final : public SOCKADDR_IN {
  public:
    uint16_t sa_family() const override { return ptr_->sa_family; }
    void sa_family(uint16_t sa_family) override { ptr_->sa_family = sa_family; }

    uint16_t sin_port() const override { return ntohs(ptr_->sin_port); }
    void sin_port(uint16_t sin_port) override { ptr_->sin_port = htons(sin_port); }

    guest_ptr<const uint8_t[]> sin_addr() const override { return sin_addr_; }
    guest_ptr<uint8_t[]> sin_addr() override { return sin_addr_; }

    guest_ptr<const char[]> sa_data() const override { return sa_data_; }
    guest_ptr<char[]> sa_data() override { return sa_data_; }

    // Helper functions
    /**
     * @brief Get the IP address as a string
     */
    std::string inet_ntoa() const override {
        static char ip[32];
        snprintf(ip, sizeof(ip), "%d.%d.%d.%d", ptr_->sin_addr[0], ptr_->sin_addr[1],
                 ptr_->sin_addr[2], ptr_->sin_addr[3]);
        return std::string(ip);
    }

    SOCKADDR_IN_IMPL(const guest_ptr<void>& ptr)
        : ptr_(ptr),
          sin_addr_(ptr + offsetof(_SOCKADDR_IN, sin_addr), sizeof(_SOCKADDR_IN::sin_addr)),
          sa_data_(ptr + offsetof(_SOCKADDR_IN, sa_data), sizeof(_SOCKADDR_IN::sa_data)) {}

  private:
    using _SOCKADDR_IN = structs::_SOCKADDR_IN;
    guest_ptr<_SOCKADDR_IN> ptr_;
    guest_ptr<uint8_t[]> sin_addr_;
    guest_ptr<char[]> sa_data_;
};

} // namespace ws2_32
} // namespace windows
} // namespace introvirt