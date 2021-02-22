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
#include <introvirt/windows/libraries/ws2_32/types/SOCKADDR.hh>

#include <algorithm>

namespace introvirt {
namespace windows {
namespace ws2_32 {

namespace structs {

struct _SOCKADDR {
    uint16_t sa_family;
    char sa_data[14];
};

}; // namespace structs

class SOCKADDR_IMPL final : public SOCKADDR {
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

    SOCKADDR_IMPL(const GuestVirtualAddress& gva) : gva_(gva), data_(gva) {}

  private:
    GuestVirtualAddress gva_;
    guest_ptr<structs::_SOCKADDR> data_;
};

} // namespace ws2_32
} // namespace windows
} // namespace introvirt