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

#include <introvirt/windows/libraries/ws2_32/types/FLOWSPEC.hh>

#include <cstdint>
#include <memory>

namespace introvirt {
namespace windows {
namespace ws2_32 {

namespace structs {

struct _FLOWSPEC {
    uint32_t TokenRate;
    uint32_t TokenBucketSize;
    uint32_t PeakBandwidth;
    uint32_t Latency;
    uint32_t DelayVariation;
    uint32_t ServiceType;
    uint32_t MaxSduSize;
    uint32_t MinimumPolicedSize;
};

} // namespace structs

class FLOWSPEC_IMPL final : public FLOWSPEC {
  public:
    uint32_t TokenRate() const override { return ptr_->TokenRate; }
    void TokenRate(uint32_t TokenRate) override { ptr_->TokenRate = TokenRate; }

    uint32_t TokenBucketSize() const override { return ptr_->TokenBucketSize; }
    void TokenBucketSize(uint32_t TokenBucketSize) override {
        ptr_->TokenBucketSize = TokenBucketSize;
    }

    uint32_t PeakBandwidth() const override { return ptr_->PeakBandwidth; }
    void PeakBandwidth(uint32_t PeakBandwidth) override { ptr_->PeakBandwidth = PeakBandwidth; }

    uint32_t Latency() const override { return ptr_->Latency; }
    void Latency(uint32_t Latency) override { ptr_->Latency = Latency; }

    uint32_t DelayVariation() const override { return ptr_->DelayVariation; }
    void DelayVariation(uint32_t DelayVariation) override { ptr_->DelayVariation = DelayVariation; }

    // TODO: This is actually a SERVICETYPE
    uint32_t ServiceType() const override { return ptr_->ServiceType; }
    void ServiceType(uint32_t ServiceType) override { ptr_->ServiceType = ServiceType; }

    uint32_t MaxSduSize() const override { return ptr_->MaxSduSize; }
    void MaxSduSize(uint32_t MaxSduSize) override { ptr_->MaxSduSize = MaxSduSize; }

    uint32_t MinimumPolicedSize() const override { return ptr_->MinimumPolicedSize; }
    void MinimumPolicedSize(uint32_t MinimumPolicedSize) override {
        ptr_->MinimumPolicedSize = MinimumPolicedSize;
    }

    FLOWSPEC_IMPL(const guest_ptr<void>& ptr) : ptr_(ptr) {}

  private:
    guest_ptr<structs::_FLOWSPEC> ptr_;
};

} // namespace ws2_32
} // namespace windows
} // namespace introvirt