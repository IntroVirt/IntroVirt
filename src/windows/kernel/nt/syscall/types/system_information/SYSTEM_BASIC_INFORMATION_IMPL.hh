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

#include "SYSTEM_INFORMATION_IMPL.hh"

#include <introvirt/windows/kernel/nt/syscall/types/system_information/SYSTEM_BASIC_INFORMATION.hh>

namespace introvirt {
namespace windows {
namespace nt {

namespace structs {

struct _SYSTEM_BASIC_INFORMATION {
    uint32_t Reserved;                     // Size=4 Offset=0
    uint32_t TimerResolution;              // Size=4 Offset=4
    uint32_t PageSize;                     // Size=4 Offset=8
    uint32_t NumberOfPhysicalPages;        // Size=4 Offset=12
    uint32_t LowestPhysicalPageNumber;     // Size=4 Offset=16
    uint32_t HighestPhysicalPageNumber;    // Size=4 Offset=20
    uint32_t AllocationGranularity;        // Size=4 Offset=24
    uint32_t MinimumUserModeAddress;       // Size=4 Offset=28
    uint32_t MaximumUserModeAddress;       // Size=4 Offset=32
    uint32_t ActiveProcessorsAffinityMask; // Size=4 Offset=36
    uint8_t NumberOfProcessors;            // Size=1 Offset=40
};

static_assert(sizeof(_SYSTEM_BASIC_INFORMATION) == 44);

} // namespace structs

using SYSTEM_BASIC_INFORMATION_IMPL_BASE =
    SYSTEM_INFORMATION_IMPL<SYSTEM_BASIC_INFORMATION, structs::_SYSTEM_BASIC_INFORMATION>;

class SYSTEM_BASIC_INFORMATION_IMPL final : public SYSTEM_BASIC_INFORMATION_IMPL_BASE {
  public:
    uint32_t TimerResolution() const override { return this->data_->TimerResolution; }
    void TimerResolution(uint32_t TimerResolution) override {
        this->data_->TimerResolution = TimerResolution;
    }

    uint32_t PageSize() const override { return this->data_->PageSize; }
    void PageSize(uint32_t PageSize) override { this->data_->PageSize = PageSize; }

    uint32_t NumberOfPhysicalPages() const override { return this->data_->NumberOfPhysicalPages; }
    void NumberOfPhysicalPages(uint32_t NumberOfPhysicalPages) override {
        this->data_->NumberOfPhysicalPages = NumberOfPhysicalPages;
    }

    uint32_t LowestPhysicalPageNumber() const override {
        return this->data_->LowestPhysicalPageNumber;
    }
    void LowestPhysicalPageNumber(uint32_t LowestPhysicalPageNumber) override {
        this->data_->LowestPhysicalPageNumber = LowestPhysicalPageNumber;
    }

    uint32_t HighestPhysicalPageNumber() const override {
        return this->data_->HighestPhysicalPageNumber;
    }
    void HighestPhysicalPageNumber(uint32_t HighestPhysicalPageNumber) override {
        this->data_->HighestPhysicalPageNumber = HighestPhysicalPageNumber;
    }

    uint32_t AllocationGranularity() const override { return this->data_->AllocationGranularity; }
    void AllocationGranularity(uint32_t AllocationGranularity) override {
        this->data_->AllocationGranularity = AllocationGranularity;
    }

    uint32_t MinimumUserModeAddress() const override { return this->data_->MinimumUserModeAddress; }
    void MinimumUserModeAddress(uint32_t MinimumUserModeAddress) override {
        this->data_->MinimumUserModeAddress = MinimumUserModeAddress;
    }

    uint32_t MaximumUserModeAddress() const override { return this->data_->MaximumUserModeAddress; }
    void MaximumUserModeAddress(uint32_t MaximumUserModeAddress) override {
        this->data_->MaximumUserModeAddress = MaximumUserModeAddress;
    }

    uint32_t ActiveProcessorsAffinityMask() const override {
        return this->data_->ActiveProcessorsAffinityMask;
    }
    void ActiveProcessorsAffinityMask(uint32_t ActiveProcessorsAffinityMask) override {
        this->data_->ActiveProcessorsAffinityMask = ActiveProcessorsAffinityMask;
    }

    uint8_t NumberOfProcessors() const override { return this->data_->NumberOfProcessors; }
    void NumberOfProcessors(uint8_t NumberOfProcessors) override {
        this->data_->NumberOfProcessors = NumberOfProcessors;
    }

    void write(std::ostream& os, const std::string& linePrefix = "") const override;
    Json::Value json() const override;

    SYSTEM_BASIC_INFORMATION_IMPL(const GuestVirtualAddress& gva, uint32_t buffer_size)
        : SYSTEM_BASIC_INFORMATION_IMPL_BASE(SYSTEM_INFORMATION_CLASS::SystemBasicInformation, gva,
                                             buffer_size) {}
};

} // namespace nt
} // namespace windows
} // namespace introvirt