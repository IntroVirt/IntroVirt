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

#include <introvirt/windows/libraries/crypt32/types/CRYPT_VERIFY_MESSAGE_PARA.hh>

#include <introvirt/core/memory/guest_ptr.hh>

#include <cstdint>

namespace introvirt {
namespace windows {
namespace crypt32 {

namespace structs {

template <typename PtrType>
struct _CRYPT_VERIFY_MESSAGE_PARA {
    uint32_t cbSize;
    uint32_t dwMsgAndCertEncodingType;
    PtrType hCryptProv;
    guest_member_ptr<void, PtrType> pfnGetSignerCertificate;
    guest_member_ptr<void, PtrType> pvGetArg;
    guest_member_ptr<void, PtrType> pStrongSignPara;
};

} // namespace structs

template <typename PtrType>
class CRYPT_VERIFY_MESSAGE_PARA_IMPL : public CRYPT_VERIFY_MESSAGE_PARA {
  public:
    uint32_t cbSize() const override { return ptr_->cbSize; }
    void cbSize(uint32_t cbSize) override { ptr_->cbSize = cbSize; }

    uint32_t dwMsgAndCertEncodingType() const override { return ptr_->dwMsgAndCertEncodingType; }
    void dwMsgAndCertEncodingType(uint32_t dwMsgAndCertEncodingType) override {
        ptr_->dwMsgAndCertEncodingType = dwMsgAndCertEncodingType;
    }

    HCRYPTPROV_LEGACY hCryptProv() const override { return ptr_->hCryptProv; }
    void hCryptProv(HCRYPTPROV_LEGACY hCryptProv) override { ptr_->hCryptProv = hCryptProv; }

    guest_ptr<void> pfnGetSignerCertificate() const override {
        return ptr_->pfnGetSignerCertificate.get(ptr_);
    }
    void pfnGetSignerCertificate(const guest_ptr<void>& ptr) override {
        ptr_->pfnGetSignerCertificate.set(ptr);
    }

    guest_ptr<void> pvGetArg() const override { return ptr_->pvGetArg.get(ptr_); }
    void pvGetArg(const guest_ptr<void>& ptr) override { ptr_->pvGetArg.set(ptr); }

    guest_ptr<void> pStrongSignPara() const override { return ptr_->pStrongSignPara.get(ptr_); }
    void pStrongSignPara(const guest_ptr<void>& ptr) override { ptr_->pStrongSignPara.set(ptr); }

    CRYPT_VERIFY_MESSAGE_PARA_IMPL(const guest_ptr<void>& ptr) : ptr_(ptr) {}

  private:
    guest_ptr<structs::_CRYPT_VERIFY_MESSAGE_PARA<PtrType>> ptr_;
};

} // namespace crypt32
} // namespace windows
} // namespace introvirt