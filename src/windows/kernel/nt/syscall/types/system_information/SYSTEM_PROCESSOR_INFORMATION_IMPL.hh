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

#include <introvirt/windows/kernel/nt/syscall/types/system_information/SYSTEM_PROCESSOR_INFORMATION.hh>

namespace introvirt {
namespace windows {
namespace nt {

namespace structs {

struct _SYSTEM_PROCESSOR_INFORMATION {
    uint16_t ProcessorArchitecture; // Size=2 Offset=0
    uint16_t ProcessorLevel;        // Size=2 Offset=2
    uint16_t ProcessorRevision;     // Size=2 Offset=4
    uint16_t MaximumProcessors;     // Size=2 Offset=6
    uint32_t ProcessorFeatureBits;  // Size=4 Offset=8
};

static_assert(sizeof(_SYSTEM_PROCESSOR_INFORMATION) == 0xC);

} // namespace structs

using SYSTEM_PROCESSOR_INFORMATION_IMPL_BASE =
    SYSTEM_INFORMATION_IMPL<SYSTEM_PROCESSOR_INFORMATION, structs::_SYSTEM_PROCESSOR_INFORMATION>;

class SYSTEM_PROCESSOR_INFORMATION_IMPL final : public SYSTEM_PROCESSOR_INFORMATION_IMPL_BASE {
  public:
    uint16_t ProcessorArchitecture() const override { return this->ptr_->ProcessorArchitecture; }
    void ProcessorArchitecture(uint16_t ProcessorArchitecture) override {
        this->ptr_->ProcessorArchitecture = ProcessorArchitecture;
    }

    uint16_t ProcessorLevel() const override { return this->ptr_->ProcessorLevel; }
    void ProcessorLevel(uint16_t ProcessorLevel) override {
        this->ptr_->ProcessorLevel = ProcessorLevel;
    }

    uint16_t ProcessorRevision() const override { return this->ptr_->ProcessorRevision; }
    void ProcessorRevision(uint16_t ProcessorRevision) override {
        this->ptr_->ProcessorRevision = ProcessorRevision;
    }

    uint16_t MaximumProcessors() const override { return this->ptr_->MaximumProcessors; }
    void MaximumProcessors(uint16_t MaximumProcessors) override {
        this->ptr_->MaximumProcessors = MaximumProcessors;
    }

    uint32_t ProcessorFeatureBits() const override { return this->ptr_->ProcessorFeatureBits; }
    void ProcessorFeatureBits(uint32_t ProcessorFeatureBits) override {
        this->ptr_->ProcessorFeatureBits = ProcessorFeatureBits;
    }

    void write(std::ostream& os, const std::string& linePrefix = "") const override;
    Json::Value json() const override;

    SYSTEM_PROCESSOR_INFORMATION_IMPL(const guest_ptr<void>& ptr, uint32_t buffer_size)
        : SYSTEM_PROCESSOR_INFORMATION_IMPL_BASE(
              SYSTEM_INFORMATION_CLASS::SystemProcessorInformation, ptr, buffer_size) {}
};

} // namespace nt
} // namespace windows
} // namespace introvirt