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
#include <introvirt/windows/libraries/kernel32/types/PROCESS_INFORMATION.hh>

namespace introvirt {
namespace windows {
namespace kernel32 {

namespace structs {

template <typename PtrType>
struct _PROCESS_INFORMATION {
    PtrType hProcess;
    PtrType hThread;
    uint32_t dwProcessId;
    uint32_t dwThreadId;
};

} // namespace structs

template <typename PtrType>
class PROCESS_INFORMATION_IMPL final : public PROCESS_INFORMATION {
  public:
    uint64_t hProcess() const override;
    void hProcess(uint64_t hProcess) override;

    uint64_t hThread() const override;
    void hThread(uint64_t hThread) override;

    uint32_t dwProcessId() const override;
    void dwProcessId(uint32_t dwProcessId) override;

    uint32_t dwThreadId() const override;
    void dwThreadId(uint32_t dwThreadId) override;

    GuestVirtualAddress address() const override;

    PROCESS_INFORMATION_IMPL(const GuestVirtualAddress& gva);
    ~PROCESS_INFORMATION_IMPL() override = default;

  private:
    GuestVirtualAddress gva_;
    guest_ptr<structs::_PROCESS_INFORMATION<PtrType>> buffer_;
};

} // namespace kernel32
} // namespace windows
} // namespace introvirt