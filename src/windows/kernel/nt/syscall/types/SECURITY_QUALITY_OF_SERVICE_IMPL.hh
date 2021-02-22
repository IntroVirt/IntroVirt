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
#include <introvirt/windows/kernel/nt/syscall/types/SECURITY_QUALITY_OF_SERVICE.hh>

namespace introvirt {
namespace windows {
namespace nt {

namespace structs {

struct _SECURITY_QUALITY_OF_SERVICE {
    uint32_t Length;
    uint32_t ImpersonationLevel;
    SECURITY_CONTEXT_TRACKING_MODE ContextTrackingMode;
    uint8_t EffectiveOnly;
};

static_assert(sizeof(_SECURITY_QUALITY_OF_SERVICE) == 0xC);

} // namespace structs

class SECURITY_QUALITY_OF_SERVICE_IMPL final : public SECURITY_QUALITY_OF_SERVICE {
  public:
    uint32_t Length() const override { return data_->Length; }
    void Length(uint32_t Length) override { data_->Length = Length; }

    SECURITY_IMPERSONATION_LEVEL ImpersonationLevel() const override {
        return static_cast<SECURITY_IMPERSONATION_LEVEL>(data_->ImpersonationLevel);
    }
    void ImpersonationLevel(SECURITY_IMPERSONATION_LEVEL ImpersonationLevel) override {
        data_->ImpersonationLevel = ImpersonationLevel;
    }

    SECURITY_CONTEXT_TRACKING_MODE ContextTrackingMode() const override {
        return data_->ContextTrackingMode;
    }
    void ContextTrackingMode(SECURITY_CONTEXT_TRACKING_MODE ContextTrackingMode) override {
        data_->ContextTrackingMode = ContextTrackingMode;
    }

    bool EffectiveOnly() const override { return data_->EffectiveOnly; }
    void EffectiveOnly(bool EffectiveOnly) override { data_->EffectiveOnly = EffectiveOnly; }

    SECURITY_QUALITY_OF_SERVICE_IMPL(const GuestVirtualAddress& gva);

  private:
    const GuestVirtualAddress gva_;
    guest_ptr<structs::_SECURITY_QUALITY_OF_SERVICE> data_;
};

} // namespace nt
} // namespace windows
} // namespace introvirt
