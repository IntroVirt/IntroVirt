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

#include "SYSTEM_INFORMATION.hh"

namespace introvirt {
namespace windows {
namespace nt {

class SYSTEM_BASIC_INFORMATION : public SYSTEM_INFORMATION {
  public:
    virtual uint32_t TimerResolution() const = 0;
    virtual void TimerResolution(uint32_t TimerResolution) = 0;

    virtual uint32_t PageSize() const = 0;
    virtual void PageSize(uint32_t PageSize) = 0;

    /**
     * @returns The Physical Memory "Total" value in taskmgr
     */
    virtual uint32_t NumberOfPhysicalPages() const = 0;
    virtual void NumberOfPhysicalPages(uint32_t NumberOfPhysicalPages) = 0;

    virtual uint32_t LowestPhysicalPageNumber() const = 0;
    virtual void LowestPhysicalPageNumber(uint32_t LowestPhysicalPageNumber) = 0;

    virtual uint32_t HighestPhysicalPageNumber() const = 0;
    virtual void HighestPhysicalPageNumber(uint32_t HighestPhysicalPageNumber) = 0;

    virtual uint32_t AllocationGranularity() const = 0;
    virtual void AllocationGranularity(uint32_t AllocationGranularity) = 0;

    virtual uint32_t MinimumUserModeAddress() const = 0;
    virtual void MinimumUserModeAddress(uint32_t MinimumUserModeAddress) = 0;

    virtual uint32_t MaximumUserModeAddress() const = 0;
    virtual void MaximumUserModeAddress(uint32_t MaximumUserModeAddress) = 0;

    virtual uint32_t ActiveProcessorsAffinityMask() const = 0;
    virtual void ActiveProcessorsAffinityMask(uint32_t ActiveProcessorsAffinityMask) = 0;

    virtual uint8_t NumberOfProcessors() const = 0;
    virtual void NumberOfProcessors(uint8_t NumberOfProcessors) = 0;
};

} // namespace nt
} // namespace windows
} // namespace introvirt
