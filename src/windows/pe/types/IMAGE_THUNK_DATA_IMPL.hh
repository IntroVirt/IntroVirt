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

#include <introvirt/windows/pe/types/IMAGE_THUNK_DATA.hh>

#include <introvirt/core/domain/Vcpu.hh>
#include <introvirt/core/memory/guest_ptr.hh>

namespace introvirt {
namespace windows {
namespace pe {

namespace structs {

template <typename PtrType>
struct _IMAGE_THUNK_DATA {
    union {
        PtrType ForwarderString;
        PtrType Function;
        PtrType Ordinal;
        PtrType AddressOfData;
    };
};

struct _IMAGE_IMPORT_BY_NAME {
    uint16_t Hint;
    int8_t Name[1];
};

} // namespace structs

template <typename PtrType>
class IMAGE_THUNK_DATA_IMPL final : public IMAGE_THUNK_DATA {
  public:
    bool imported_by_name() const override { return importByName.get(); }
    bool imported_by_ordinal() const override { return !imported_by_name(); }
    const std::string& Function() const override { return function_; }
    uint64_t AddressOfData() const override { return ptr_->AddressOfData; }
    uint64_t Ordinal() const override { return ptr_->Ordinal; }

    // TODO: Break this out into a separate class?
    uint16_t Hint() const override {
        if (importByName) {
            return importByName->Hint;
        }
        return 0;
    }

    IMAGE_THUNK_DATA_IMPL(const guest_ptr<void>& image_base, const guest_ptr<void>& ptr)
        : ptr_(ptr) {

        static const uint64_t IMPORT_ORDINAL_FLAGS = (1LL << ((sizeof(PtrType) * 8) - 1));

        guest_ptr<void> pImportByName;
        if (!(ptr_->AddressOfData & IMPORT_ORDINAL_FLAGS) && ptr_->AddressOfData) {
            pImportByName = image_base + ptr_->Function;
        }

        if (pImportByName) {
            importByName.reset(pImportByName);
            const guest_ptr<void> function_str_ptr(pImportByName + 2);
            function_ = map_guest_cstring(function_str_ptr).str();
        }
    }

  private:
    guest_ptr<structs::_IMAGE_THUNK_DATA<PtrType>> ptr_;
    guest_ptr<structs::_IMAGE_IMPORT_BY_NAME> importByName;
    std::string function_;
};

} // namespace pe
} // namespace windows
} // namespace introvirt