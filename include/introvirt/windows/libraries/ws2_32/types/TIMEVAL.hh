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
 * @see https://docs.microsoft.com/en-us/windows/win32/api/winsock/ns-winsock-timeval
 */
class TIMEVAL {
  public:
    virtual int32_t tv_sec() const = 0;
    virtual void tv_sec(int32_t tv_sec) = 0;

    virtual int32_t tv_usec() const = 0;
    virtual void tv_usec(int32_t tv_usec) = 0;

    static std::shared_ptr<TIMEVAL> make_shared(const guest_ptr<void>& ptr, bool x64);
};

} // namespace ws2_32
} // namespace windows
} // namespace introvirt