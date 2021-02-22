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
    PtrType pfnAlloc;
    PtrType pfnFree;
};

} // namespace structs

template <typename PtrType>
class CRYPT_DECODE_PARA_IMPL final : public CRYPT_DECODE_PARA {
  public:
    uint32_t cbSize() const override { return data_->cbSize; }
    void cbSize(uint32_t cbSize) override { data_->cbSize = cbSize; }

    GuestVirtualAddress pfnAlloc() const override { return gva_.create(data_->pfnAlloc); }
    void pfnAlloc(const GuestVirtualAddress& gva) override {
        data_->pfnAlloc = gva.virtual_address();
    }

    GuestVirtualAddress pfnFree() const override { return gva_.create(data_->pfnFree); }
    void pfnFree(const GuestVirtualAddress& gva) override {
        data_->pfnFree = gva.virtual_address();
    }

    CRYPT_DECODE_PARA_IMPL(const GuestVirtualAddress& gva) : gva_(gva), data_(gva) {}

  private:
    GuestVirtualAddress gva_;
    guest_ptr<structs::_CRYPT_DECODE_PARA<PtrType>> data_;
};

} // namespace crypt32
} // namespace windows
} // namespace introvirt