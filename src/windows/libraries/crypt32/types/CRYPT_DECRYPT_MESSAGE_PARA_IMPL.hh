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

#include <introvirt/windows/libraries/crypt32/types/CRYPT_DECRYPT_MESSAGE_PARA.hh>

#include <introvirt/core/memory/guest_ptr.hh>

#include <cstdint>

namespace introvirt {
namespace windows {
namespace crypt32 {

namespace structs {

template <typename PtrType>
struct _CRYPT_DECRYPT_MESSAGE_PARA {
    uint32_t cbSize;
    uint32_t dwMsgAndCertEncodingType;
    uint32_t cCertStore;
    PtrType prghCertStore;
    uint32_t dwFlags;
};

} // namespace structs

template <typename PtrType>
class CRYPT_DECRYPT_MESSAGE_PARA_IMPL final : public CRYPT_DECRYPT_MESSAGE_PARA {
  public:
    uint32_t cbSize() const override { return data_->cbSize; }
    void cbSize(uint32_t cbSize) override {}

    uint32_t dwMsgAndCertEncodingType() const override { return data_->dwMsgAndCertEncodingType; }
    void dwMsgAndCertEncodingType(uint32_t dwMsgAndCertEncodingType) override {
        data_->dwMsgAndCertEncodingType = dwMsgAndCertEncodingType;
    }

    uint32_t cCertStore() const override { return data_->cCertStore; }
    void cCertStore(uint32_t cCertStore) override { data_->cCertStore = cCertStore; }

    GuestVirtualAddress prghCertStore() const override { return gva_.create(data_->prghCertStore); }
    void prghCertStore(const GuestVirtualAddress& gva) override {
        data_->prghCertStore = gva.virtual_address();
    }

    uint32_t dwFlags() const override { return data_->dwFlags; }
    void dwFlags(uint32_t dwFlags) override { data_->dwFlags = dwFlags; }

    CRYPT_DECRYPT_MESSAGE_PARA_IMPL(const GuestVirtualAddress& gva) : gva_(gva), data_(gva) {}

  private:
    GuestVirtualAddress gva_;
    guest_ptr<structs::_CRYPT_DECRYPT_MESSAGE_PARA<PtrType>> data_;
};

} // namespace crypt32
} // namespace windows
} // namespace introvirt