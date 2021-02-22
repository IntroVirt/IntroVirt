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
#include <introvirt/windows/libraries/kernel32/types/STARTUPINFO.hh>

namespace introvirt {
namespace windows {
namespace kernel32 {

namespace structs {

template <typename PtrType>
struct _STARTUPINFO {
    uint32_t cb;
    PtrType lpReserved;
    PtrType lpDesktop;
    PtrType lpTitle;
    uint32_t dwX;
    uint32_t dwY;
    uint32_t dwXSize;
    uint32_t dwYSize;
    uint32_t dwXCountChars;
    uint32_t dwYCountChars;
    uint32_t dwFillAttribute;
    uint32_t dwFlags;
    int32_t wShowWindow;
    int32_t cbReserved2;
    PtrType lpReserved2;
    PtrType hStdInput;
    PtrType hStdOutput;
    PtrType hStdError;
};

} // namespace structs

template <typename PtrType>
class STARTUPINFO_IMPL final : public STARTUPINFO {
  public:
    uint32_t cb() const override;
    void cb(uint32_t cb) override;

    GuestVirtualAddress lpReserved() const override;
    void lpReserved(const GuestVirtualAddress& lpReserved) override;

    GuestVirtualAddress lpDesktop() const override;
    void lpDesktop(const GuestVirtualAddress& lpDesktop) override;

    GuestVirtualAddress lpTitle() const override;
    void lpTitle(const GuestVirtualAddress& lpTitle) override;

    uint32_t dwX() const override;
    void dwX(uint32_t dwX) override;

    uint32_t dwY() const override;
    void dwY(uint32_t dwY) override;

    uint32_t dwXSize() const override;
    void dwXSize(uint32_t dwXSize) override;

    uint32_t dwYSize() const override;
    void dwYSize(uint32_t dwYSize) override;

    uint32_t dwXCountChars() const override;
    void dwXCountChars(uint32_t dwXCountChars) override;

    uint32_t dwYCountChars() const override;
    void dwYCountChars(uint32_t dwYCountChars) override;

    uint32_t dwFillAttribute() const override;
    void dwFillAttribute(uint32_t dwFillAttribute) override;

    uint32_t dwFlags() const override;
    void dwFlags(uint32_t dwFlags) override;

    int32_t wShowWindow() const override;
    void wShowWindow(int32_t wShowWindow) override;

    int32_t cbReserved2() const override;
    void cbReserved2(int32_t cbReserved2) override;

    GuestVirtualAddress lpReserved2() const override;
    void lpReserved2(const GuestVirtualAddress& lpReserved2) override;

    uint64_t hStdInput() const override;
    void hStdInput(uint64_t hStdInput) override;

    uint64_t hStdOutput() const override;
    void hStdOutput(uint64_t hStdOutput) override;

    uint64_t hStdError() const override;
    void hStdError(uint64_t hStdError) override;

    GuestVirtualAddress address() const override;

    STARTUPINFO_IMPL(const GuestVirtualAddress& gva);
    ~STARTUPINFO_IMPL() override = default;

  private:
    GuestVirtualAddress gva_;
    guest_ptr<structs::_STARTUPINFO<PtrType>> buffer_;
};

} // namespace kernel32
} // namespace windows
} // namespace introvirt