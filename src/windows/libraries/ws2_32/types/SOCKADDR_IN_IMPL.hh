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
        char sa_data[14];
    };
};

}; // namespace structs

class SOCKADDR_IN_IMPL final : public SOCKADDR_IN {
  public:
    uint16_t sa_family() const override { return data_->sa_family; }
    void sa_family(uint16_t sa_family) override { data_->sa_family = sa_family; }

    std::array<char, 14> sa_data() const override {
        std::array<char, 14> result;
        std::copy_n(data_->sa_data, sizeof(data_->sa_data), result.data());
        return result;
    }
    void sa_data(const std::array<char, 14>& sa_data) override {
        std::copy_n(sa_data.data(), sizeof(data_->sa_data), data_->sa_data);
    }

    uint16_t sin_port() const override { return ntohs(data_->sin_port); }
    void sin_port(uint16_t sin_port) override { data_->sin_port = htons(sin_port); }

    std::array<uint8_t, 4> sin_addr() const override {
        std::array<uint8_t, 4> result;
        std::copy_n(data_->sin_addr, sizeof(data_->sin_addr), result.data());
        return result;
    }

    void sin_addr(const std::array<uint8_t, 4>& sin_addr) override {
        std::copy_n(sin_addr.data(), sizeof(data_->sin_addr), data_->sin_addr);
    }

    // Helper functions
    /**
     * @brief Get the IP address as a string
     */
    std::string inet_ntoa() const override {
        static char ip[32];
        snprintf(ip, sizeof(ip), "%d.%d.%d.%d", data_->sin_addr[0], data_->sin_addr[1],
                 data_->sin_addr[2], data_->sin_addr[3]);
        return std::string(ip);
    }

    SOCKADDR_IN_IMPL(const GuestVirtualAddress& gva) : gva_(gva), data_(gva) {}

  private:
    GuestVirtualAddress gva_;
    guest_ptr<structs::_SOCKADDR_IN> data_;
};

} // namespace ws2_32
} // namespace windows
} // namespace introvirt