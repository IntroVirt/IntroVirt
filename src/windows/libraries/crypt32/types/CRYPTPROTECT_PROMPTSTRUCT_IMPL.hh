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

#include <introvirt/core/memory/guest_ptr.hh>
#include <introvirt/windows/libraries/crypt32/types/CRYPTPROTECT_PROMPTSTRUCT.hh>

namespace introvirt {
namespace windows {
namespace crypt32 {

namespace structs {

template <typename PtrType>
struct _CRYPTPROTECT_PROMPTSTRUCT {
    uint32_t cbSize;
    uint32_t dwPromptFlags;
    PtrType hwndApp;
    char szPrompt[];
};

} // namespace structs

template <typename PtrType>
class CRYPTPROTECT_PROMPTSTRUCT_IMPL final : public CRYPTPROTECT_PROMPTSTRUCT {
  public:
    uint32_t cbSize() const override { return data_->cbSize; }
    void cbSize(uint32_t cbSize) override { data_->cbSize = cbSize; }

    uint32_t dwPromptFlags() const override { return data_->dwPromptFlags; }
    void dwPromptFlags(uint32_t dwPromptFlags) override { data_->dwPromptFlags = dwPromptFlags; }

    uint64_t hwndApp() const override { return data_->hwndApp; }
    void hwndApp(uint64_t hwndApp) override { data_->hwndApp = hwndApp; }

    std::string szPrompt() const override {
        const size_t strlen = data_->cbSize - sizeof(structs::_CRYPTPROTECT_PROMPTSTRUCT<PtrType>);
        guest_ptr<char[]> mapping(gva_, strlen);
        return std::string(mapping.get(), strlen);
    }

    CRYPTPROTECT_PROMPTSTRUCT_IMPL(const GuestVirtualAddress& gva) : gva_(gva), data_(gva) {}

  private:
    const GuestVirtualAddress gva_;
    guest_ptr<structs::_CRYPTPROTECT_PROMPTSTRUCT<PtrType>> data_;
};

} // namespace crypt32
} // namespace windows
} // namespace introvirt