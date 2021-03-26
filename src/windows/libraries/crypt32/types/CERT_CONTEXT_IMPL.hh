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
    guest_member_ptr<uint8_t[], PtrType> pbCertEncoded;
    uint32_t cbCertEncoded;
    guest_member_ptr<void, PtrType> pCertInfo;
    PtrType hCertStore;
};

static_assert(sizeof(_CERT_CONTEXT<uint32_t>) == 20, "Invalid _CERT_CONTEXT size");
static_assert(sizeof(_CERT_CONTEXT<uint64_t>) == 40, "Invalid _CERT_CONTEXT size");

} // namespace structs

template <typename PtrType>
class CERT_CONTEXT_IMPL final : public CERT_CONTEXT {
  public:
    uint32_t dwCertEncodingType() const override { return ptr_->dwCertEncodingType; }
    void dwCertEncodingType(uint32_t dwCertEncodingType) override {
        ptr_->dwCertEncodingType = dwCertEncodingType;
    }

    guest_ptr<uint8_t[]> pbCertEncoded() const override {
        return ptr_->pbCertEncoded.get(ptr_, cbCertEncoded());
    }
    void pbCertEncoded(const guest_ptr<uint8_t[]>& ptr) override { ptr_->pbCertEncoded.set(ptr); }

    uint32_t cbCertEncoded() const override { return ptr_->cbCertEncoded; }
    void cbCertEncoded(uint32_t cbCertEncoded) override { ptr_->cbCertEncoded = cbCertEncoded; }

    guest_ptr<void> pCertInfo() const override { return ptr_->pCertInfo.get(ptr_); }
    void pCertInfo(const guest_ptr<void>& ptr) override { ptr_->pCertInfo.set(ptr); }

    HCERTSTORE hCertStore() const override { return ptr_->hCertStore; }
    void hCertStore(HCERTSTORE hCertStore) override { ptr_->hCertStore = hCertStore; }

    CERT_CONTEXT_IMPL(const guest_ptr<void>& ptr) : ptr_(ptr) {}

  private:
    const guest_ptr<structs::_CERT_CONTEXT<PtrType>> ptr_;
};

} // namespace crypt32
} // namespace windows
} // namespace introvirt