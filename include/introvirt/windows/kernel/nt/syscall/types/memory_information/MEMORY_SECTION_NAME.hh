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

#include <string>

namespace introvirt {
namespace windows {
namespace nt {

/**
 * https://msdn.microsoft.com/en-us/library/windows/hardware/dn957515(v=vs.85).aspx
 */
class MEMORY_SECTION_NAME : public MEMORY_INFORMATION {
  public:
    virtual const std::string& SectionFileName() const = 0;
    virtual void SectionFileName(const std::string& value) = 0;

    static std::unique_ptr<MEMORY_SECTION_NAME>
    make_unique(const NtKernel& kernel, const GuestVirtualAddress& gva, uint32_t buffer_size);
};

} // namespace nt
} // namespace windows

namespace inject {

template <>
class GuestAllocation<windows::nt::MEMORY_SECTION_NAME>
    : public GuestAllocationComplexBase<windows::nt::MEMORY_SECTION_NAME> {
  public:
    explicit GuestAllocation();

  private:
    std::optional<GuestAllocation<uint8_t[]>> buffer_;
};

} // namespace inject
} // namespace introvirt
