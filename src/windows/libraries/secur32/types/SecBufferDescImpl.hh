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
#include <introvirt/windows/libraries/secur32/types/SecBufferDesc.hh>

#include <cstdint>

namespace introvirt {
namespace windows {
namespace secur32 {

namespace structs {

template <typename PtrType>
struct _SecBufferDesc {
    uint32_t ulVersion;
    uint32_t cBuffers;
    PtrType pBuffers;
};

} // namespace structs

template <typename PtrType>
class SecBufferDescImpl final : public SecBufferDesc {
  public:
    uint32_t ulVersion() const override { return data_->ulVersion; }
    void ulVersion(uint32_t ulVersion) override { data_->ulVersion = ulVersion; }

    uint32_t cBuffers() const override { return data_->cBuffers; }
    void cBuffers(uint32_t cBuffers) override { data_->cBuffers = cBuffers; }

    GuestVirtualAddress pBuffers() const override { return gva_.create(data_->pBuffers); }
    void pBuffers(const GuestVirtualAddress& gva) override {
        data_->pBuffers = gva.virtual_address();
    }

    SecBufferDescImpl(const GuestVirtualAddress& gva) : gva_(gva), data_(gva) {}

  private:
    GuestVirtualAddress gva_;
    guest_ptr<structs::_SecBufferDesc<PtrType>> data_;
};

} // namespace secur32
} // namespace windows
} // namespace introvirt
