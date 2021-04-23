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
#include <introvirt/windows/libraries/secur32/types/SecBuffer.hh>

#include <cstdint>

namespace introvirt {
namespace windows {
namespace secur32 {

namespace structs {

template <typename PtrType>
struct _SecBuffer {
    uint32_t cbBuffer;
    uint32_t BufferType;
    guest_member_ptr<uint8_t[], PtrType> pvBuffer;
};

} // namespace structs

template <typename PtrType>
class SecBufferImpl final : public SecBuffer {
  public:
    uint32_t cbBuffer() const override { return ptr_->cbBuffer; }
    void cbBuffer(uint32_t value) override { ptr_->cbBuffer = value; }

    uint32_t BufferType() const override { return ptr_->BufferType; }
    void BufferType(uint32_t value) override { ptr_->BufferType = value; }

    guest_ptr<uint8_t[]> pvBuffer() const override { return ptr_->pvBuffer.get(ptr_, cbBuffer()); }
    void pvBuffer(const guest_ptr<uint8_t[]>& ptr) override { ptr_->pvBuffer.set(ptr); }

    SecBufferImpl(const guest_ptr<void>& ptr) : ptr_(ptr) {}

  private:
    guest_ptr<structs::_SecBuffer<PtrType>> ptr_;
};

} // namespace secur32
} // namespace windows
} // namespace introvirt
