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
    guest_member_ptr<void, PtrType> pvHashAuxInfo;
};

} // namespace structs

template <typename PtrType>
class CRYPT_HASH_MESSAGE_PARA_IMPL final : public CRYPT_HASH_MESSAGE_PARA {
  public:
    uint32_t cbSize() const override { return ptr_->cbSize; }
    void cbSize(uint32_t cbSize) override { ptr_->cbSize = cbSize; }

    uint32_t dwMsgEncodingType() const override { return ptr_->dwMsgEncodingType; }
    void dwMsgEncodingType(uint32_t dwMsgEncodingType) override {
        ptr_->dwMsgEncodingType = dwMsgEncodingType;
    }

    HCRYPTPROV_LEGACY hCryptProv() const override { return ptr_->hCryptProv; }
    void hCryptProv(HCRYPTPROV_LEGACY hCryptProv) override { ptr_->hCryptProv = hCryptProv; }

    const CRYPT_ALGORITHM_IDENTIFIER& HashAlgorithm() const override { return HashAlgorithm_; }
    CRYPT_ALGORITHM_IDENTIFIER& HashAlgorithm() override { return HashAlgorithm_; }

    guest_ptr<void> pvHashAuxInfo() const override { return ptr_->pvHashAuxInfo.get(ptr_); }
    void pvHashAuxInfo(const guest_ptr<void>& ptr) override { ptr_->pvHashAuxInfo.set(ptr); }

    CRYPT_HASH_MESSAGE_PARA_IMPL(const guest_ptr<void>& ptr)
        : ptr_(ptr), HashAlgorithm_(ptr + offsetof(_CRYPT_HASH_MESSAGE_PARA, HashAlgorithm)) {}

  private:
    using _CRYPT_HASH_MESSAGE_PARA = structs::_CRYPT_HASH_MESSAGE_PARA<PtrType>;
    guest_ptr<structs::_CRYPT_HASH_MESSAGE_PARA<PtrType>> ptr_;
    CRYPT_ALGORITHM_IDENTIFIER_IMPL<PtrType> HashAlgorithm_;
};

} // namespace crypt32
} // namespace windows
} // namespace introvirt