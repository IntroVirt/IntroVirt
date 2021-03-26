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

#include "STARTUPINFOA.hh"

#include <introvirt/core/injection/GuestAllocation.hh>
#include <introvirt/core/memory/guest_ptr.hh>

#include <cstdint>
#include <memory>

namespace introvirt {
namespace windows {
namespace kernel32 {

class STARTUPINFOW {
  public:
    virtual uint32_t cb() const = 0;
    virtual void cb(uint32_t cb) = 0;

    virtual guest_ptr<char16_t[]> lpReserved() const = 0;
    virtual void lpReserved(const guest_ptr<char16_t[]>& lpReserved) = 0;

    virtual guest_ptr<char16_t[]> lpDesktop() const = 0;
    virtual void lpDesktop(const guest_ptr<char16_t[]>& lpDesktop) = 0;

    virtual guest_ptr<char16_t[]> lpTitle() const = 0;
    virtual void lpTitle(const guest_ptr<char16_t[]>& lpTitle) = 0;

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

    virtual uint16_t wShowWindow() const = 0;
    virtual void wShowWindow(uint16_t wShowWindow) = 0;

    virtual uint16_t cbReserved2() const = 0;
    virtual void cbReserved2(uint16_t cbReserved2) = 0;

    virtual guest_ptr<uint8_t[]> lpReserved2() const = 0;
    virtual void lpReserved2(const guest_ptr<uint8_t[]>& lpReserved2) = 0;

    virtual uint64_t hStdInput() const = 0;
    virtual void hStdInput(uint64_t hStdInput) = 0;

    virtual uint64_t hStdOutput() const = 0;
    virtual void hStdOutput(uint64_t hStdOutput) = 0;

    virtual uint64_t hStdError() const = 0;
    virtual void hStdError(uint64_t hStdError) = 0;

    virtual guest_ptr<void> address() const = 0;

    static std::shared_ptr<STARTUPINFOW> make_shared(const guest_ptr<void>& ptr, bool x64);

    virtual ~STARTUPINFOW() = default;
};

} // namespace kernel32
} // namespace windows

namespace inject {

template <>
class GuestAllocation<windows::kernel32::STARTUPINFOW> final
    : public GuestAllocationComplexBase<windows::kernel32::STARTUPINFOW> {
  public:
    explicit GuestAllocation();
};

} // namespace inject

} // namespace introvirt