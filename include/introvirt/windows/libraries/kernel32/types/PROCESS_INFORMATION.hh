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

class PROCESS_INFORMATION {
  public:
    virtual uint64_t hProcess() const = 0;
    virtual void hProcess(uint64_t hProcess) = 0;

    virtual uint64_t hThread() const = 0;
    virtual void hThread(uint64_t hThread) = 0;

    virtual uint32_t dwProcessId() const = 0;
    virtual void dwProcessId(uint32_t dwProcessId) = 0;

    virtual uint32_t dwThreadId() const = 0;
    virtual void dwThreadId(uint32_t dwThreadId) = 0;

    virtual GuestVirtualAddress address() const = 0;

    static std::unique_ptr<PROCESS_INFORMATION> make_unique(const GuestVirtualAddress& gva);

    virtual ~PROCESS_INFORMATION() = default;
};

} // namespace kernel32
} // namespace windows

namespace inject {

template <>
class GuestAllocation<windows::kernel32::PROCESS_INFORMATION>
    : public GuestAllocationComplexBase<windows::kernel32::PROCESS_INFORMATION> {
  public:
    explicit GuestAllocation();

  private:
    std::optional<GuestAllocation<uint8_t[]>> buffer_;
};

} // namespace inject

} // namespace introvirt