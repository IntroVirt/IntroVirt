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

#include "MEMORY_INFORMATION.hh"

#include <introvirt/core/injection/GuestAllocation.hh>
#include <introvirt/windows/kernel/nt/const/MEMORY_ALLOCATION_TYPE.hh>
#include <introvirt/windows/kernel/nt/const/PAGE_PROTECTION.hh>
#include <introvirt/windows/kernel/nt/fwd.hh>

namespace introvirt {
namespace windows {
namespace nt {

/**
 * @brief MEMORY_BASIC_INFORMATION structure parser
 *
 * @see https://msdn.microsoft.com/en-us/library/windows/hardware/dn957515(v=vs.85).aspx
 */
class MEMORY_BASIC_INFORMATION : public MEMORY_INFORMATION {
  public:
    virtual uint64_t BaseAddress() const = 0;
    virtual uint64_t AllocationBase() const = 0;
    virtual PAGE_PROTECTION AllocationProtect() const = 0;
    virtual uint64_t RegionSize() const = 0;
    virtual MEMORY_ALLOCATION_TYPE State() const = 0;
    virtual PAGE_PROTECTION Protect() const = 0;
    virtual MEMORY_ALLOCATION_TYPE Type() const = 0;

    static std::unique_ptr<MEMORY_BASIC_INFORMATION>
    make_unique(const NtKernel& kernel, const GuestVirtualAddress& gva, uint32_t buffer_size);
};

} // namespace nt
} // namespace windows

namespace inject {

template <>
class GuestAllocation<windows::nt::MEMORY_BASIC_INFORMATION>
    : public GuestAllocationComplexBase<windows::nt::MEMORY_BASIC_INFORMATION> {
  public:
    explicit GuestAllocation();

  private:
    std::optional<GuestAllocation<uint8_t[]>> buffer_;
};

} // namespace inject
} // namespace introvirt
