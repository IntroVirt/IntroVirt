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

#include <introvirt/windows/libraries/crypt32/types/CRYPT_DECODE_PARA.hh>

#include <introvirt/core/memory/guest_ptr.hh>

#include <cstdint>

namespace introvirt {
namespace windows {
namespace crypt32 {

namespace structs {

template <typename PtrType>
struct _CRYPT_DECODE_PARA {
    uint32_t cbSize;
    guest_member_ptr<void, PtrType> pfnAlloc;
    guest_member_ptr<void, PtrType> pfnFree;
};

static_assert(sizeof(_CRYPT_DECODE_PARA<uint32_t>) == 12);
static_assert(sizeof(_CRYPT_DECODE_PARA<uint64_t>) == 24);

} // namespace structs

template <typename PtrType>
class CRYPT_DECODE_PARA_IMPL final : public CRYPT_DECODE_PARA {
  public:
    uint32_t cbSize() const override { return ptr_->cbSize; }
    void cbSize(uint32_t cbSize) override { ptr_->cbSize = cbSize; }

    guest_ptr<void> pfnAlloc() const override { return ptr_->pfnAlloc.get(ptr_); }
    void pfnAlloc(const guest_ptr<void>& ptr) override { ptr_->pfnAlloc.set(ptr); }

    guest_ptr<void> pfnFree() const override { return ptr_->pfnFree.get(ptr_); }
    void pfnFree(const guest_ptr<void>& ptr) override { ptr_->pfnFree.set(ptr); }

    CRYPT_DECODE_PARA_IMPL(const guest_ptr<void>& ptr) : ptr_(ptr) {}

  private:
    guest_ptr<structs::_CRYPT_DECODE_PARA<PtrType>> ptr_;
};

} // namespace crypt32
} // namespace windows
} // namespace introvirt