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
#include "core/domain/VcpuImpl.hh"

#include "RegisterGuard.hh"

namespace introvirt {
namespace inject {

void RegisterGuard::release() { original_.reset(); }

RegisterGuard::RegisterGuard(Vcpu& vcpu) : vcpu_(vcpu), original_(vcpu.clone()) {}

RegisterGuard::~RegisterGuard() {
    if (!original_)
        return;

    // SECTEPE: this restore reads+writes the vcpu registers. During a syscall
    // injection's stack-unwind the vcpu may be running again, so registers()
    // would throw EBUSY ("vcpu running") — and a throw from a destructor while
    // ALREADY unwinding calls std::terminate (the dominant residual Win11 abort,
    // backtrace: ~RegisterGuard -> registers().cold -> _Unwind_Resume). Pause the
    // vcpu (refcounted; a no-op net if a guard already holds it) so the restore
    // is always on a readable vcpu, and never propagate out of this destructor.
    bool paused_here = false;
    try {
        vcpu_.pause();
        paused_here = true;
    } catch (...) {
        // could not pause (degraded) — best-effort restore below, still no throw
    }
    try {
    auto& regs = vcpu_.registers();
    regs.rsi(original_->registers().rsi());
    regs.rdi(original_->registers().rdi());
    regs.rsp(original_->registers().rsp());
    regs.rbp(original_->registers().rbp());
    regs.rip(original_->registers().rip());
    regs.rax(original_->registers().rax());
    regs.rbx(original_->registers().rbx());
    regs.rcx(original_->registers().rcx());
    regs.rdx(original_->registers().rdx());
    regs.r8(original_->registers().r8());
    regs.r9(original_->registers().r9());
    regs.r10(original_->registers().r10());
    regs.r11(original_->registers().r11());
    regs.r12(original_->registers().r12());
    regs.r13(original_->registers().r13());
    regs.r14(original_->registers().r14());
    regs.r15(original_->registers().r15());
    regs.rflags(original_->registers().rflags());
    } catch (...) {
        // best-effort restore; never propagate out of a destructor.
    }
    if (paused_here) {
        try {
            vcpu_.resume();
        } catch (...) {
        }
    }
}

} // namespace inject
} // namespace introvirt