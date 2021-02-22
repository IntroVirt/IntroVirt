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

#include "CRYPTOAPI_BLOB_IMPL.hh"

#include <introvirt/windows/libraries/crypt32/types/CRYPT_ALGORITHM_IDENTIFIER.hh>

#include <introvirt/core/memory/guest_ptr.hh>

#include <cstdint>

namespace introvirt {
namespace windows {
namespace crypt32 {

namespace structs {

template <typename PtrType>
struct _CRYPT_ALGORITHM_IDENTIFIER {
    PtrType pszObjId;
    _CRYPTOAPI_BLOB<PtrType> Parameters;
};

} // namespace structs

template <typename PtrType>
class CRYPT_ALGORITHM_IDENTIFIER_IMPL final : public CRYPT_ALGORITHM_IDENTIFIER {
  public:
    GuestVirtualAddress pszObjId() const override { return gva_.create(data_->pszObjId); }
    void pszObjId(const GuestVirtualAddress& gva) override {
        data_->pszObjId = gva.virtual_address();
    }

    const CRYPTOAPI_BLOB& Parameters() const override { return blob_; }
    CRYPTOAPI_BLOB& Parameters() override { return blob_; }

    std::string szObjId() const override {
        auto mapping = map_guest_cstr(pszObjId());
        return std::string(mapping.get(), mapping.length());
    }

    CRYPT_ALGORITHM_IDENTIFIER_IMPL(const GuestVirtualAddress& gva)
        : gva_(gva), data_(gva),
          blob_(gva_ + offsetof(structs::_CRYPT_ALGORITHM_IDENTIFIER<PtrType>, Parameters)) {}

  private:
    GuestVirtualAddress gva_;
    guest_ptr<structs::_CRYPT_ALGORITHM_IDENTIFIER<PtrType>> data_;
    CRYPTOAPI_BLOB_IMPL<PtrType> blob_;
};

} // namespace crypt32
} // namespace windows
} // namespace introvirt