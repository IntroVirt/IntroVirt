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

#include <introvirt/core/injection/GuestAllocation.hh>
#include <introvirt/core/memory/GuestVirtualAddress.hh>

#include <cstdint>
#include <memory>

namespace introvirt {
namespace windows {
namespace kernel32 {

// Values for dwFlags
constexpr unsigned int STARTF_USESHOWWINDOW = 0x00000001;

// Values for wShowWindow
constexpr unsigned int SW_HIDE = 0;

class STARTUPINFO {
  public:
    virtual uint32_t cb() const = 0;
    virtual void cb(uint32_t cb) = 0;

    virtual GuestVirtualAddress lpReserved() const = 0;
    virtual void lpReserved(const GuestVirtualAddress& lpReserved) = 0;

    virtual GuestVirtualAddress lpDesktop() const = 0;
    virtual void lpDesktop(const GuestVirtualAddress& lpDesktop) = 0;

    virtual GuestVirtualAddress lpTitle() const = 0;
    virtual void lpTitle(const GuestVirtualAddress& lpTitle) = 0;

    virtual uint32_t dwX() const = 0;
    virtual void dwX(uint32_t dwX) = 0;

    virtual uint32_t dwY() const = 0;
    virtual void dwY(uint32_t dwY) = 0;

    virtual uint32_t dwXSize() const = 0;
    virtual void dwXSize(uint32_t dwXSize) = 0;

    virtual uint32_t dwYSize() const = 0;
    virtual void dwYSize(uint32_t dwYSize) = 0;

    virtual uint32_t dwXCountChars() const = 0;
    virtual void dwXCountChars(uint32_t dwXCountChars) = 0;

    virtual uint32_t dwYCountChars() const = 0;
    virtual void dwYCountChars(uint32_t dwYCountChars) = 0;

    virtual uint32_t dwFillAttribute() const = 0;
    virtual void dwFillAttribute(uint32_t dwFillAttribute) = 0;

    virtual uint32_t dwFlags() const = 0;
    virtual void dwFlags(uint32_t dwFlags) = 0;

    virtual int32_t wShowWindow() const = 0;
    virtual void wShowWindow(int32_t wShowWindow) = 0;

    virtual int32_t cbReserved2() const = 0;
    virtual void cbReserved2(int32_t cbReserved2) = 0;

    virtual GuestVirtualAddress lpReserved2() const = 0;
    virtual void lpReserved2(const GuestVirtualAddress& lpReserved2) = 0;

    virtual uint64_t hStdInput() const = 0;
    virtual void hStdInput(uint64_t hStdInput) = 0;

    virtual uint64_t hStdOutput() const = 0;
    virtual void hStdOutput(uint64_t hStdOutput) = 0;

    virtual uint64_t hStdError() const = 0;
    virtual void hStdError(uint64_t hStdError) = 0;

    virtual GuestVirtualAddress address() const = 0;

    static std::unique_ptr<STARTUPINFO> make_unique(const GuestVirtualAddress& gva);

    virtual ~STARTUPINFO() = default;
};

} // namespace kernel32
} // namespace windows

namespace inject {

template <>
class GuestAllocation<windows::kernel32::STARTUPINFO>
    : public GuestAllocationComplexBase<windows::kernel32::STARTUPINFO> {
  public:
    explicit GuestAllocation();

  private:
    std::optional<GuestAllocation<uint8_t[]>> buffer_;
};

} // namespace inject

} // namespace introvirt