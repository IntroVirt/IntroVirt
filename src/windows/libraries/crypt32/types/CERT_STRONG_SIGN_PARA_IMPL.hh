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
        PtrType pvInfo;
        PtrType pSerializedInfo;
        PtrType pszOID;
    };
};

} // namespace structs

template <typename PtrType>
class CERT_STRONG_SIGN_PARA_IMPL final : public CERT_STRONG_SIGN_PARA {
  public:
    uint32_t cbSize() const override { return data_->cbSize; }
    void cbSize(uint32_t cbSize) override { data_->cbSize = cbSize; }

    uint32_t dwInfoChoice() const override { return data_->dwInfoChoice; }
    void dwInfoChoice(uint32_t dwInfoChoice) override { data_->dwInfoChoice = dwInfoChoice; }

    GuestVirtualAddress pvInfo() const override { return gva_.create(data_->pvInfo); }
    void pvInfo(const GuestVirtualAddress& gva) override { data_->pvInfo = gva.virtual_address(); }

    GuestVirtualAddress pSerializedInfo() const override {
        return gva_.create(data_->pSerializedInfo);
    }
    void pSerializedInfo(const GuestVirtualAddress& gva) override {
        data_->pSerializedInfo = gva.virtual_address();
    }

    GuestVirtualAddress pszOID() const override { return gva_.create(data_->pszOID); }
    void pszOID(const GuestVirtualAddress& gva) override { data_->pszOID = gva.virtual_address(); }

    CERT_STRONG_SIGN_PARA_IMPL(const GuestVirtualAddress& gva) : gva_(gva), data_(gva) {}

  private:
    GuestVirtualAddress gva_;
    guest_ptr<structs::_CERT_STRONG_SIGN_PARA<PtrType>> data_;
};

} // namespace crypt32
} // namespace windows
} // namespace introvirt