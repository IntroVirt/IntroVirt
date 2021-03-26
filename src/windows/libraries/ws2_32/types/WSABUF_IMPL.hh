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

#include <introvirt/windows/libraries/ws2_32/types/WSABUF.hh>

namespace introvirt {
namespace windows {
namespace ws2_32 {

namespace structs {

template <typename PtrType>
struct _WSABUF {
    uint32_t len;
    PtrType buf;
};
} // namespace structs

template <typename PtrType>
class WSABUF_IMPL final : public WSABUF {
  public:
    uint32_t len() const override { return ptr_->len; }
    void len(uint32_t len) override { ptr_->len = len; }

    guest_ptr<const uint8_t[]> buf() const override {
        return const_cast<WSABUF_IMPL<PtrType>*>(this)->buf();
    }
    guest_ptr<uint8_t[]> buf() override {
        return guest_ptr<uint8_t[]>(ptr_.domain(), ptr_->buf, ptr_.page_directory(), len());
    }

    void buf(const guest_ptr<uint8_t[]>& buf) override { ptr_->buf = buf.address(); }

    WSABUF_IMPL(const guest_ptr<void>& ptr) : ptr_(ptr) {}

  private:
    guest_ptr<structs::_WSABUF<PtrType>> ptr_;
};

} // namespace ws2_32
} // namespace windows
} // namespace introvirt