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

#include <introvirt/core/domain/Vcpu.hh>
#include <introvirt/core/exception/CommandFailedException.hh>

namespace introvirt {
namespace inject {

/**
 * @brief RAII pause of a SINGLE vcpu (KVM_VCPU_PAUSE refcount).
 *
 * Register access throws EBUSY if this vcpu is running, so hold the pause
 * except around guest execution. Pause only this vcpu, and never throw from
 * the destructor.
 */
class VcpuPauseGuard final {
  public:
    explicit VcpuPauseGuard(Vcpu& vcpu) {
        try {
            vcpu.pause();
            vcpu_ = &vcpu;
        } catch (...) {
            vcpu_ = nullptr;
        }
    }

    ~VcpuPauseGuard() {
        if (vcpu_ != nullptr) {
            try {
                vcpu_->resume();
            } catch (...) {
            }
        }
    }

    VcpuPauseGuard(const VcpuPauseGuard&) = delete;
    VcpuPauseGuard& operator=(const VcpuPauseGuard&) = delete;
    VcpuPauseGuard(VcpuPauseGuard&&) = delete;
    VcpuPauseGuard& operator=(VcpuPauseGuard&&) = delete;

  private:
    Vcpu* vcpu_ = nullptr;
};

} // namespace inject
} // namespace introvirt
