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

#include <introvirt/windows/kernel/nt/syscall/types/system_information/SYSTEM_BASIC_PERFORMANCE_INFORMATION.hh>

namespace introvirt {
namespace windows {
namespace nt {

namespace structs {

struct _SYSTEM_BASIC_PERFORMANCE_INFORMATION {
    uint32_t AvailablePages; // Size=4 Offset=0
    uint32_t CommittedPages; // Size=4 Offset=4
    uint32_t CommitLimit;    // Size=4 Offset=8
    uint32_t PeakCommitment; // Size=4 Offset=12
};

static_assert(sizeof(_SYSTEM_BASIC_PERFORMANCE_INFORMATION) == 0x10);

} // namespace structs

using SYSTEM_BASIC_PERFORMANCE_INFORMATION_IMPL_BASE =
    SYSTEM_INFORMATION_IMPL<SYSTEM_BASIC_PERFORMANCE_INFORMATION,
                            structs::_SYSTEM_BASIC_PERFORMANCE_INFORMATION>;

class SYSTEM_BASIC_PERFORMANCE_INFORMATION_IMPL final
    : public SYSTEM_BASIC_PERFORMANCE_INFORMATION_IMPL_BASE {
  public:
    uint32_t AvailablePages() const override { return this->data_->AvailablePages; }
    void AvailablePages(uint32_t AvailablePages) override {
        this->data_->AvailablePages = AvailablePages;
    }

    uint32_t CommittedPages() const override { return this->data_->CommittedPages; }
    void CommittedPages(uint32_t CommittedPages) override {
        this->data_->CommittedPages = CommittedPages;
    }

    uint32_t CommitLimit() const override { return this->data_->CommitLimit; }
    void CommitLimit(uint32_t CommitLimit) override { this->data_->CommitLimit = CommitLimit; }

    uint32_t PeakCommitment() const override { return this->data_->PeakCommitment; }
    void PeakCommitment(uint32_t PeakCommitment) override {
        this->data_->PeakCommitment = PeakCommitment;
    }

    void write(std::ostream& os, const std::string& linePrefix = "") const override;
    Json::Value json() const override;

    SYSTEM_BASIC_PERFORMANCE_INFORMATION_IMPL(const GuestVirtualAddress& gva, uint32_t buffer_size)
        : SYSTEM_BASIC_PERFORMANCE_INFORMATION_IMPL_BASE(
              SYSTEM_INFORMATION_CLASS::SystemBasicPerformanceInformation, gva, buffer_size) {}
};

} // namespace nt
} // namespace windows
} // namespace introvirt