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
#include <introvirt/windows/libraries/kernel32/types/STARTUPINFOW.hh>

namespace introvirt {
namespace windows {
namespace kernel32 {

namespace structs {

template <typename PtrType>
struct _STARTUPINFOW {
    uint32_t cb;
    guest_member_ptr<char16_t[], PtrType> lpReserved;
    guest_member_ptr<char16_t[], PtrType> lpDesktop;
    guest_member_ptr<char16_t[], PtrType> lpTitle;
    uint32_t dwX;
    uint32_t dwY;
    uint32_t dwXSize;
    uint32_t dwYSize;
    uint32_t dwXCountChars;
    uint32_t dwYCountChars;
    uint32_t dwFillAttribute;
    uint32_t dwFlags;
    uint16_t wShowWindow;
    uint16_t cbReserved2;
    guest_member_ptr<uint8_t[], PtrType> lpReserved2;
    PtrType hStdInput;
    PtrType hStdOutput;
    PtrType hStdError;
};

} // namespace structs

template <typename PtrType>
class STARTUPINFOW_IMPL final : public STARTUPINFOW {
  public:
    uint32_t cb() const override { return ptr_->cb; }
    void cb(uint32_t cb) override { ptr_->cb = cb; }

    guest_ptr<char16_t[]> lpReserved() const override { return ptr_->lpReserved.wstring(ptr_); }
    void lpReserved(const guest_ptr<char16_t[]>& lpReserved) override {
        ptr_->lpReserved.set(lpReserved);
    }

    guest_ptr<char16_t[]> lpDesktop() const override { return ptr_->lpDesktop.wstring(ptr_); }
    void lpDesktop(const guest_ptr<char16_t[]>& lpDesktop) override {
        ptr_->lpDesktop.set(lpDesktop);
    }

    guest_ptr<char16_t[]> lpTitle() const override { return ptr_->lpTitle.wstring(ptr_); }
    void lpTitle(const guest_ptr<char16_t[]>& lpTitle) override { ptr_->lpTitle.set(lpTitle); }

    uint32_t dwX() const override { return ptr_->dwX; }
    void dwX(uint32_t dwX) override { ptr_->dwX = dwX; }

    uint32_t dwY() const override { return ptr_->dwY; }
    void dwY(uint32_t dwY) override { ptr_->dwY = dwY; }

    uint32_t dwXSize() const override { return ptr_->dwXSize; }
    void dwXSize(uint32_t dwXSize) override { ptr_->dwXSize = dwXSize; }

    uint32_t dwYSize() const override { return ptr_->dwYSize; }
    void dwYSize(uint32_t dwYSize) override { ptr_->dwYSize = dwYSize; }

    uint32_t dwXCountChars() const override { return ptr_->dwXCountChars; }
    void dwXCountChars(uint32_t dwXCountChars) override { ptr_->dwXCountChars = dwXCountChars; }

    uint32_t dwYCountChars() const override { return ptr_->dwYCountChars; }
    void dwYCountChars(uint32_t dwYCountChars) override { ptr_->dwYCountChars = dwYCountChars; }

    uint32_t dwFillAttribute() const override { return ptr_->dwFillAttribute; }
    void dwFillAttribute(uint32_t dwFillAttribute) override {
        ptr_->dwFillAttribute = dwFillAttribute;
    }

    uint32_t dwFlags() const override { return ptr_->dwFlags; }
    void dwFlags(uint32_t dwFlags) override { ptr_->dwFlags = dwFlags; }

    uint16_t wShowWindow() const override { return ptr_->wShowWindow; }
    void wShowWindow(uint16_t wShowWindow) override { ptr_->wShowWindow = wShowWindow; }

    uint16_t cbReserved2() const override { return ptr_->cbReserved2; }
    void cbReserved2(uint16_t cbReserved2) override { ptr_->cbReserved2 = cbReserved2; }

    guest_ptr<uint8_t[]> lpReserved2() const override {
        return ptr_->lpReserved2.get(ptr_, cbReserved2());
    }
    void lpReserved2(const guest_ptr<uint8_t[]>& lpReserved2) override {
        ptr_->lpReserved2.set(lpReserved2);
    }

    uint64_t hStdInput() const override { return ptr_->hStdInput; }
    void hStdInput(uint64_t hStdInput) override { ptr_->hStdInput = hStdInput; }

    uint64_t hStdOutput() const override { return ptr_->hStdOutput; }
    void hStdOutput(uint64_t hStdOutput) override { ptr_->hStdOutput = hStdOutput; }

    uint64_t hStdError() const override { return ptr_->hStdError; }
    void hStdError(uint64_t hStdError) override { ptr_->hStdError = hStdError; }

    guest_ptr<void> address() const override { return ptr_; }

    STARTUPINFOW_IMPL(const guest_ptr<void>& ptr) : ptr_(ptr) {}

    ~STARTUPINFOW_IMPL() override = default;

  private:
    guest_ptr<structs::_STARTUPINFOW<PtrType>> ptr_;
};

} // namespace kernel32
} // namespace windows
} // namespace introvirt