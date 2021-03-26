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

#include <introvirt/windows/libraries/crypt32/types/CERT_STRONG_SIGN_PARA.hh>

#include <introvirt/core/memory/guest_ptr.hh>

#include <cassert>
#include <cstdint>

namespace introvirt {
namespace windows {
namespace crypt32 {

namespace structs {

template <typename PtrType>
struct _CERT_STRONG_SIGN_PARA {
    uint32_t cbSize;
    uint32_t dwInfoChoice;
    union {
        guest_member_ptr<void, PtrType> pvInfo;
        guest_member_ptr<void, PtrType> pSerializedInfo;
        guest_member_ptr<char[], PtrType> pszOID;
    };
};

} // namespace structs

template <typename PtrType>
class CERT_STRONG_SIGN_PARA_IMPL final : public CERT_STRONG_SIGN_PARA {
  public:
    uint32_t cbSize() const override { return ptr_->cbSize; }
    void cbSize(uint32_t cbSize) override { ptr_->cbSize = cbSize; }

    uint32_t dwInfoChoice() const override { return ptr_->dwInfoChoice; }
    void dwInfoChoice(uint32_t dwInfoChoice) override { ptr_->dwInfoChoice = dwInfoChoice; }

    guest_ptr<void> pvInfo() const override { return ptr_->pvInfo.get(ptr_); }
    void pvInfo(const guest_ptr<void>& ptr) override { ptr_->pvInfo.set(ptr); }

    guest_ptr<void> pSerializedInfo() const override { return ptr_->pSerializedInfo.get(ptr_); }
    void pSerializedInfo(const guest_ptr<void>& ptr) override { ptr_->pSerializedInfo.set(ptr); }
    guest_ptr<char[]> pszOID() const override {
        // TODO: We should be checking dwInfoChoice to make sure this is a string
        return ptr_->pszOID.cstring(ptr_);
    }
    void pszOID(const guest_ptr<char[]>& ptr) override { ptr_->pszOID.set(ptr); }

    CERT_STRONG_SIGN_PARA_IMPL(const guest_ptr<void>& ptr) : ptr_(ptr) {}

  private:
    using _CERT_STRONG_SIGN_PARA = structs::_CERT_STRONG_SIGN_PARA<PtrType>;
    guest_ptr<_CERT_STRONG_SIGN_PARA> ptr_;
};

} // namespace crypt32
} // namespace windows
} // namespace introvirt