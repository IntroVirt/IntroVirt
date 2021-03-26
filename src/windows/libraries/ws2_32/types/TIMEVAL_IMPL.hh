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

#include <introvirt/windows/libraries/ws2_32/types/TIMEVAL.hh>

#include <cstdint>
#include <memory>

namespace introvirt {
namespace windows {
namespace ws2_32 {

namespace structs {

struct _TIMEVAL {
    int32_t tv_sec;
    int32_t tv_usec;
};

} // namespace structs

class TIMEVAL_IMPL final : public TIMEVAL {
  public:
    int32_t tv_sec() const override { return ptr_->tv_sec; }
    void tv_sec(int32_t tv_sec) override { ptr_->tv_sec = tv_sec; }

    int32_t tv_usec() const override { return ptr_->tv_usec; }
    void tv_usec(int32_t tv_usec) override { ptr_->tv_usec = tv_usec; }

    TIMEVAL_IMPL(const guest_ptr<void>& ptr) : ptr_(ptr) {}

  private:
    guest_ptr<structs::_TIMEVAL> ptr_;
};

} // namespace ws2_32
} // namespace windows
} // namespace introvirt
