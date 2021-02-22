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

#include "CRYPT_ALGORITHM_IDENTIFIER_IMPL.hh"

#include <introvirt/windows/libraries/crypt32/types/CRYPT_HASH_MESSAGE_PARA.hh>

#include <introvirt/core/memory/guest_ptr.hh>

#include <cstdint>

namespace introvirt {
namespace windows {
namespace crypt32 {

namespace structs {

template <typename PtrType>
struct _CRYPT_HASH_MESSAGE_PARA {
    uint32_t cbSize;
    uint32_t dwMsgEncodingType;
    PtrType hCryptProv;
    _CRYPT_ALGORITHM_IDENTIFIER<PtrType> HashAlgorithm;
    PtrType pvHashAuxInfo;
};

} // namespace structs

template <typename PtrType>
class CRYPT_HASH_MESSAGE_PARA_IMPL final : public CRYPT_HASH_MESSAGE_PARA {
  public:
    uint32_t cbSize() const override { return data_->cbSize; }
    void cbSize(uint32_t cbSize) override { data_->cbSize = cbSize; }

    uint32_t dwMsgEncodingType() const override { return data_->dwMsgEncodingType; }
    void dwMsgEncodingType(uint32_t dwMsgEncodingType) override {
        data_->dwMsgEncodingType = dwMsgEncodingType;
    }

    HCRYPTPROV_LEGACY hCryptProv() const override { return data_->hCryptProv; }
    void hCryptProv(HCRYPTPROV_LEGACY hCryptProv) override { data_->hCryptProv = hCryptProv; }

    const CRYPT_ALGORITHM_IDENTIFIER& HashAlgorithm() const override { return HashAlgorithm_; }
    CRYPT_ALGORITHM_IDENTIFIER& HashAlgorithm() override { return HashAlgorithm_; }

    GuestVirtualAddress pvHashAuxInfo() const override { return gva_.create(data_->pvHashAuxInfo); }
    void pvHashAuxInfo(const GuestVirtualAddress& gva) override {
        data_->pvHashAuxInfo = gva.virtual_address();
    }

    CRYPT_HASH_MESSAGE_PARA_IMPL(const GuestVirtualAddress& gva)
        : gva_(gva), data_(gva),
          HashAlgorithm_(gva_ +
                         offsetof(structs::_CRYPT_HASH_MESSAGE_PARA<PtrType>, HashAlgorithm)) {}

  private:
    GuestVirtualAddress gva_;
    guest_ptr<structs::_CRYPT_HASH_MESSAGE_PARA<PtrType>> data_;
    CRYPT_ALGORITHM_IDENTIFIER_IMPL<PtrType> HashAlgorithm_;
};

} // namespace crypt32
} // namespace windows
} // namespace introvirt