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

#include <introvirt/windows/libraries/crypt32/types/CERT_CONTEXT.hh>

#include <introvirt/core/memory/guest_ptr.hh>

#include <cstdint>

namespace introvirt {
namespace windows {
namespace crypt32 {

namespace structs {

template <typename PtrType>
struct _CERT_CONTEXT {
    uint32_t dwCertEncodingType;
    PtrType pbCertEncoded;
    uint32_t cbCertEncoded;
    PtrType pCertInfo;
    PtrType hCertStore;
};

} // namespace structs

template <typename PtrType>
class CERT_CONTEXT_IMPL final : public CERT_CONTEXT {
  public:
    uint32_t dwCertEncodingType() const override { return data_->dwCertEncodingType; }
    void dwCertEncodingType(uint32_t dwCertEncodingType) override {
        data_->dwCertEncodingType = dwCertEncodingType;
    }

    GuestVirtualAddress pbCertEncoded() const override { return gva_.create(data_->pbCertEncoded); }
    void pbCertEncoded(const GuestVirtualAddress& gva) override {
        data_->pbCertEncoded = gva.virtual_address();
    }

    uint32_t cbCertEncoded() const override { return data_->cbCertEncoded; }
    void cbCertEncoded(uint32_t cbCertEncoded) override { data_->cbCertEncoded = cbCertEncoded; }

    GuestVirtualAddress pCertInfo() const override { return gva_.create(data_->pCertInfo); }
    void pCertInfo(const GuestVirtualAddress& gva) override {
        data_->pCertInfo = gva.virtual_address();
    }

    HCERTSTORE hCertStore() const override { return data_->hCertStore; }
    void hCertStore(HCERTSTORE hCertStore) override { data_->hCertStore = hCertStore; }

    CERT_CONTEXT_IMPL(const GuestVirtualAddress& gva) : gva_(gva), data_(gva) {}

  private:
    GuestVirtualAddress gva_;
    guest_ptr<structs::_CERT_CONTEXT<PtrType>> data_;
};

} // namespace crypt32
} // namespace windows
} // namespace introvirt