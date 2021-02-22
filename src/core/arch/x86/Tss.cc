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

#include <introvirt/core/arch/x86/Registers.hh>
#include <introvirt/core/arch/x86/Tss.hh>
#include <introvirt/core/domain/Vcpu.hh>
#include <introvirt/core/memory/guest_ptr.hh>

namespace introvirt {
namespace x86 {

GuestVirtualAddress Tss::sp0() const {
    const Registers& registers = vcpu_.registers();
    auto tr = registers.tr();

    // On both 32-bit and 64-bit, the value is held at base + 4
    uint64_t pSp0 = tr.base() + 4;

    uint64_t result;
    if (vcpu_.registers().efer().lme()) {
        // 64-bit mode
        result = *guest_ptr<uint64_t>(GuestVirtualAddress(vcpu_, pSp0));
    } else {
        // 32-bit mode
        result = *guest_ptr<uint32_t>(GuestVirtualAddress(vcpu_, pSp0));
    }

    return GuestVirtualAddress(vcpu_, result);
}

Tss::Tss(const Vcpu& vcpu) : vcpu_(vcpu) {}

Tss::~Tss() = default;

} // namespace x86
} // namespace introvirt
