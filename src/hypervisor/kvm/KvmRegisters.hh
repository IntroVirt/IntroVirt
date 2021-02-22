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

#include "kvm_introspection.hh"

#include <introvirt/core/arch/x86/Registers.hh>
#include <introvirt/util/compiler.hh>

#include <memory>

namespace introvirt {
namespace kvm {

class KvmRegisters final : public x86::Registers {
  public:
    uint64_t rax() const override;
    void rax(uint64_t val) override;

    uint64_t rbx() const override;
    void rbx(uint64_t val) override;

    uint64_t rcx() const override;
    void rcx(uint64_t val) override;

    uint64_t rdx() const override;
    void rdx(uint64_t val) override;

    uint64_t r15() const override;
    void r15(uint64_t val) override;

    uint64_t r14() const override;
    void r14(uint64_t val) override;

    uint64_t r13() const override;
    void r13(uint64_t val) override;

    uint64_t r12() const override;
    void r12(uint64_t val) override;

    uint64_t r11() const override;
    void r11(uint64_t val) override;

    uint64_t r10() const override;
    void r10(uint64_t val) override;

    uint64_t r9() const override;
    void r9(uint64_t val) override;

    uint64_t r8() const override;
    void r8(uint64_t val) override;

    uint64_t rsi() const override;
    void rsi(uint64_t val) override;

    uint64_t rdi() const override;
    void rdi(uint64_t val) override;

    uint64_t rsp() const override;
    void rsp(uint64_t val) override;

    uint64_t rbp() const override;
    void rbp(uint64_t val) override;

    uint64_t rip() const override;
    void rip(uint64_t val) override;

    x86::Flags& rflags() override;
    const x86::Flags& rflags() const override;
    void rflags(const x86::Flags& val) override;

    x86::Efer efer() const override;

    x86::Cr0 cr0() const override;
    uint64_t cr2() const override;
    uint64_t cr3() const override;
    x86::Cr4 cr4() const override;
    uint64_t cr8() const override;

    // Non virtual method used by clone()
    void cr3(uint64_t value);

    uint64_t gdtr_base() const override;
    uint32_t gdtr_limit() const override;

    uint64_t idtr_base() const override;
    uint32_t idtr_limit() const override;

    bool cs_long_mode() const override;

    x86::Segment cs() const override;
    void cs(x86::Segment seg) override;

    x86::Segment ds() const override;
    x86::Segment es() const override;
    x86::Segment fs() const override;
    x86::Segment gs() const override;
    x86::Segment ss() const override;
    x86::Segment tr() const override;
    x86::Segment ldt() const override;

    uint64_t msr(x86::Msr msr) const override;
    void msr(x86::Msr msr, uint64_t val) override;

    /**
     * @brief Copy the vcpu registers into this structure
     *
     * The caller should first have paused the VCPU!
     *
     * @throws CommandFailedException If there was an error fetching the registers
     */
    void read();

    /**
     * @brief Update the registers held by the VCPU
     *
     * The caller should first have paused the VCPU!
     *
     * @throws CommandFailedException If there was an error fetching the registers
     */
    void write();

    /**
     * @brief Construct a new Kvm Registers object
     *
     * @param event_data The event data to for register data
     * @param fd
     */
    KvmRegisters(struct kvm_introspection_event& event_data, int fd);

    /**
     * @brief Copy constructor
     */
    KvmRegisters(const KvmRegisters&) HOT;

    /**
     * @brief Destroy the instance
     */
    ~KvmRegisters() override;

  private:
    std::unique_ptr<kvm_introspection_event> copy_;
    struct kvm_introspection_event* event_data_;

    struct kvm_regs* regs_;
    struct kvm_sregs* sregs_;
    struct kvm_debugregs* debugregs_;

    x86::Flags rflags_;

    const int fd_;
    bool changed_regs_ = false;
    bool changed_sregs_ = false;
};

} // namespace kvm
} // namespace introvirt