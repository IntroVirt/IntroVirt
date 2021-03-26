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
    uint16_t sa_family() const override { return ptr_->sa_family; }
    void sa_family(uint16_t sa_family) override { ptr_->sa_family = sa_family; }

    guest_ptr<const char[]> sa_data() const override { return sa_data_; }
    guest_ptr<char[]> sa_data() override { return sa_data_; }

    SOCKADDR_IMPL(const guest_ptr<void>& ptr)
        : ptr_(ptr), sa_data_(ptr + offsetof(_SOCKADDR, sa_data), sizeof(_SOCKADDR::sa_data)) {}

  private:
    using _SOCKADDR = structs::_SOCKADDR;
    guest_ptr<_SOCKADDR> ptr_;
    guest_ptr<char[]> sa_data_;
};

} // namespace ws2_32
} // namespace windows
} // namespace introvirt