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

#include "FLOWSPEC_IMPL.hh"
#include "WSABUF_IMPL.hh"

#include <introvirt/windows/libraries/ws2_32/types/FD_SET.hh>

#include <cstdint>
#include <memory>

namespace introvirt {
namespace windows {
namespace ws2_32 {

namespace structs {

template <typename PtrType>
struct _FD_SET {
    uint32_t fd_count;
    PtrType fd_array[];
};

} // namespace structs

template <typename PtrType>
class FD_SET_IMPL final : public FD_SET {
  public:
    uint32_t fd_count() const override { return ptr_->fd_count; }
    void fd_count(uint32_t fd_count) override { ptr_->fd_count = fd_count; }

    guest_ptr<const guest_size_t[]> fd_array() const override { return array_; }
    guest_ptr<guest_size_t[]> fd_array() override { return array_; }

    FD_SET_IMPL(const guest_ptr<void>& ptr)
        : ptr_(ptr), array_(guest_ptr<PtrType[]>(ptr + offsetof(_FD_SET, fd_array), fd_count())) {}

  private:
    using _FD_SET = structs::_FD_SET<PtrType>;
    guest_ptr<_FD_SET> ptr_;
    guest_ptr<guest_size_t[]> array_;
};

} // namespace ws2_32
} // namespace windows
} // namespace introvirt
