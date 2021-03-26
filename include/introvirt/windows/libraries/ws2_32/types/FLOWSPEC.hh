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

#include <cstdint>
#include <memory>

namespace introvirt {
namespace windows {
namespace ws2_32 {

/**
 * @see https://docs.microsoft.com/en-us/windows/win32/api/qos/ns-qos-flowspec
 */
class FLOWSPEC {
  public:
    virtual uint32_t TokenRate() const = 0;
    virtual void TokenRate(uint32_t TokenRate) = 0;

    virtual uint32_t TokenBucketSize() const = 0;
    virtual void TokenBucketSize(uint32_t TokenBucketSize) = 0;

    virtual uint32_t PeakBandwidth() const = 0;
    virtual void PeakBandwidth(uint32_t PeakBandwidth) = 0;

    virtual uint32_t Latency() const = 0;
    virtual void Latency(uint32_t Latency) = 0;

    virtual uint32_t DelayVariation() const = 0;
    virtual void DelayVariation(uint32_t DelayVariation) = 0;

    // TODO: This is actually a SERVICETYPE
    virtual uint32_t ServiceType() const = 0;
    virtual void ServiceType(uint32_t ServiceType) = 0;

    virtual uint32_t MaxSduSize() const = 0;
    virtual void MaxSduSize(uint32_t MaxSduSize) = 0;

    virtual uint32_t MinimumPolicedSize() const = 0;
    virtual void MinimumPolicedSize(uint32_t MinimumPolicedSize) = 0;

    static std::shared_ptr<FLOWSPEC> make_shared(const guest_ptr<void>& ptr, bool x64);
};

} // namespace ws2_32
} // namespace windows
} // namespace introvirt