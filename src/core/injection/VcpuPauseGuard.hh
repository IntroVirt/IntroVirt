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
 * SECTEPE (Win11 injection). A syscall injection reads/writes the injected
 * vcpu's registers at its ctor, begin_syscall, and cleanup. Between sequential
 * injections (and after a nested verify_stack_present / suspend) the vcpu is
 * RUNNING again, so those reads hit KvmVcpu::registers()'s "vcpu running" gate
 * and throw EBUSY. The injector holds this guard during register-access regions
 * and RELEASES it only around the parts that must EXECUTE on the guest (the
 * nested verify_stack_present injections and the syscall's own run via
 * suspend()), so the register accesses are always on a paused vcpu while the
 * guest still runs the syscalls.
 *
 * Pauses ONLY the given vcpu, never peers (pausing peers deadlocks the heavy
 * create). Degrades to inert if it can't pause, and never throws from its dtor.
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
