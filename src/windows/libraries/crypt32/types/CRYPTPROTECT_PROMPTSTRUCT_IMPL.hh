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
    uint32_t cbSize() const override { return ptr_->cbSize; }
    void cbSize(uint32_t cbSize) override { ptr_->cbSize = cbSize; }

    uint32_t dwPromptFlags() const override { return ptr_->dwPromptFlags; }
    void dwPromptFlags(uint32_t dwPromptFlags) override { ptr_->dwPromptFlags = dwPromptFlags; }

    uint64_t hwndApp() const override { return ptr_->hwndApp; }
    void hwndApp(uint64_t hwndApp) override { ptr_->hwndApp = hwndApp; }

    guest_ptr<char[]> szPrompt() const override { return szPrompt_; }

    CRYPTPROTECT_PROMPTSTRUCT_IMPL(const guest_ptr<void>& ptr) : ptr_(ptr) {
        const size_t strlen = ptr_->cbSize - sizeof(_CRYPTPROTECT_PROMPTSTRUCT);
        szPrompt_.reset(ptr + offsetof(_CRYPTPROTECT_PROMPTSTRUCT, szPrompt), strlen);
    }

  private:
    using _CRYPTPROTECT_PROMPTSTRUCT = structs::_CRYPTPROTECT_PROMPTSTRUCT<PtrType>;
    guest_ptr<_CRYPTPROTECT_PROMPTSTRUCT> ptr_;
    guest_ptr<char[]> szPrompt_;
};

} // namespace crypt32
} // namespace windows
} // namespace introvirt