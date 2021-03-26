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
#include <introvirt/windows/libraries/ws2_32/types/TRANSMIT_FILE_BUFFERS.hh>

namespace introvirt {
namespace windows {
namespace ws2_32 {

namespace structs {

template <typename PtrType>
struct _TRANSMIT_FILE_BUFFERS {
    guest_member_ptr<uint8_t[], PtrType> Head;
    uint32_t HeadLength;
    guest_member_ptr<uint8_t[], PtrType> Tail;
    uint32_t TailLength;
};

}; // namespace structs

template <typename PtrType>
class TRANSMIT_FILE_BUFFERS_IMPL final : public TRANSMIT_FILE_BUFFERS {
  public:
  public:
    guest_ptr<uint8_t[]> Head() const override { return ptr_->Head.get(ptr_, HeadLength()); }
    void Head(const guest_ptr<uint8_t[]>& ptr) override { ptr_->Head.set(ptr); }

    uint32_t HeadLength() const override { return ptr_->HeadLength; }
    void HeadLength(uint32_t HeadLength) override { ptr_->HeadLength = HeadLength; }

    guest_ptr<uint8_t[]> Tail() const override { return ptr_->Tail.get(ptr_, TailLength()); }
    void Tail(const guest_ptr<uint8_t[]>& ptr) override { ptr_->Tail.set(ptr); }

    uint32_t TailLength() const override { return ptr_->TailLength; }
    void TailLength(uint32_t TailLength) override { ptr_->TailLength = TailLength; }

    TRANSMIT_FILE_BUFFERS_IMPL(const guest_ptr<void>& ptr) : ptr_(ptr) {}

  private:
    guest_ptr<structs::_TRANSMIT_FILE_BUFFERS<PtrType>> ptr_;
};

} // namespace ws2_32
} // namespace windows
} // namespace introvirt