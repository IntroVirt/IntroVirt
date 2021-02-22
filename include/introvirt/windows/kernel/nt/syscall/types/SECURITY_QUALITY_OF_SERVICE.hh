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

#include <introvirt/windows/kernel/nt/const/SECURITY_IMPERSONATION_LEVEL.hh>
#include <introvirt/windows/kernel/nt/fwd.hh>

#include <introvirt/core/memory/GuestVirtualAddress.hh>

#include <cstdint>
#include <memory>

namespace introvirt {
namespace windows {
namespace nt {

using SECURITY_CONTEXT_TRACKING_MODE = uint8_t;

class SECURITY_QUALITY_OF_SERVICE {
  public:
    virtual uint32_t Length() const = 0;
    virtual void Length(uint32_t Length) = 0;

    virtual SECURITY_IMPERSONATION_LEVEL ImpersonationLevel() const = 0;
    virtual void ImpersonationLevel(SECURITY_IMPERSONATION_LEVEL ImpersonationLevel) = 0;

    virtual SECURITY_CONTEXT_TRACKING_MODE ContextTrackingMode() const = 0;
    virtual void ContextTrackingMode(SECURITY_CONTEXT_TRACKING_MODE ContextTrackingMode) = 0;

    virtual bool EffectiveOnly() const = 0;
    virtual void EffectiveOnly(bool EffectiveOnly) = 0;

    static std::unique_ptr<SECURITY_QUALITY_OF_SERVICE> make_unique(const GuestVirtualAddress& gva);

    virtual ~SECURITY_QUALITY_OF_SERVICE() = default;
};

} /* namespace nt */
} /* namespace windows */
} /* namespace introvirt */
