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
#include <introvirt/windows/libraries/ws2_32/types/WSAOVERLAPPED.hh>

namespace introvirt {
namespace windows {
namespace ws2_32 {

namespace structs {

template <typename PtrType>
struct _WSAOVERLAPPED {
    uint32_t Internal;
    uint32_t InternalHigh;
    uint32_t Offset;
    uint32_t OffsetHigh;
    /* WSAEVENT */ PtrType hEvent;
};

}; // namespace structs

template <typename PtrType>
class WSAOVERLAPPED_IMPL final : public WSAOVERLAPPED {
  public:
    uint32_t Internal() const override { return ptr_->Internal; }
    void Internal(uint32_t Internal) override { ptr_->Internal = Internal; }

    uint32_t InternalHigh() const override { return ptr_->InternalHigh; }
    void InternalHigh(uint32_t InternalHigh) override { ptr_->InternalHigh = InternalHigh; }

    uint32_t Offset() const override { return ptr_->Offset; }
    void Offset(uint32_t Offset) override { ptr_->Offset = Offset; }

    uint32_t OffsetHigh() const override { return ptr_->OffsetHigh; }
    void OffsetHigh(uint32_t OffsetHigh) override { ptr_->OffsetHigh = OffsetHigh; }

    uint64_t hEvent() const override { return ptr_->hEvent; }
    void hEvent(uint64_t hEvent) override { ptr_->hEvent = hEvent; }

    WSAOVERLAPPED_IMPL(const guest_ptr<void>& ptr) : ptr_(ptr) {}

  private:
    guest_ptr<structs::_WSAOVERLAPPED<PtrType>> ptr_;
};

} // namespace ws2_32
} // namespace windows
} // namespace introvirt