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

#include <introvirt/windows/libraries/crypt32/types/CRYPTOAPI_BLOB.hh>

#include <introvirt/core/memory/guest_ptr.hh>

#include <cstdint>

namespace introvirt {
namespace windows {
namespace crypt32 {

namespace structs {

template <typename PtrType>
struct _CRYPTOAPI_BLOB {
    uint32_t cbData;
    PtrType pbData;
};

} // namespace structs

template <typename PtrType>
class CRYPTOAPI_BLOB_IMPL final : public CRYPTOAPI_BLOB {
  public:
    uint32_t cbData() const override { return data_->cbData; }
    void cbData(uint32_t cbData) override { data_->cbData = cbData; }

    GuestVirtualAddress pbData() const override { return gva_.create(data_->pbData); }
    void pbData(const GuestVirtualAddress& gva) override { data_->pbData = gva.virtual_address(); }

    CRYPTOAPI_BLOB_IMPL(const GuestVirtualAddress& gva) : gva_(gva), data_(gva) {}

  private:
    GuestVirtualAddress gva_;
    guest_ptr<structs::_CRYPTOAPI_BLOB<PtrType>> data_;
};

} // namespace crypt32
} // namespace windows
} // namespace introvirt