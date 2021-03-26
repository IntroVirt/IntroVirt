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

#include "SOCKET.hh"

#include <introvirt/core/memory/guest_ptr.hh>

#include <cstdint>
#include <memory>

namespace introvirt {
namespace windows {
namespace ws2_32 {

/**
 * @see https://docs.microsoft.com/en-us/windows/win32/api/winsock/ns-winsock-fd_set
 */
class FD_SET {
  public:
    virtual uint32_t fd_count() const = 0;
    virtual void fd_count(uint32_t fd_count) = 0;

    virtual guest_ptr<const guest_size_t[]> fd_array() const = 0;
    virtual guest_ptr<guest_size_t[]> fd_array() = 0;

    static std::shared_ptr<FD_SET> make_shared(const guest_ptr<void>& ptr, bool x64);
};

} // namespace ws2_32
} // namespace windows
} // namespace introvirt