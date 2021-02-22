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

#include <introvirt/core/arch/x86/Cr0.hh>
#include <introvirt/core/arch/x86/Cr4.hh>
#include <introvirt/core/arch/x86/Efer.hh>
#include <introvirt/core/arch/x86/Flags.hh>
#include <introvirt/core/arch/x86/Msr.hh>
#include <introvirt/core/arch/x86/Segment.hh>

#include <cstdint>

namespace introvirt {
namespace x86 {

/**
 * @brief A class for holding x86 register state
 */
class Registers {
  public:
    /**
     * @brief Get the rax register value
     * @return The value held by the rax register
     */
    virtual uint64_t rax() const = 0;
    /**
     * @brief Set the rax register value
     * @param val The value to set
     */
    virtual void rax(uint64_t val) = 0;

    /**
     * @brief Get the rbx register value
     * @return The value held by the rbx register
     */
    virtual uint64_t rbx() const = 0;
    /**
     * @brief Set the rbx register value
     * @param val The value to set
     */
    virtual void rbx(uint64_t val) = 0;
    /**
     * @brief Get the rcx register value
     * @return The value held by the rcx register
     */
    virtual uint64_t rcx() const = 0;
    /**
     * @brief Set the rcx register value
     * @param val The value to set
     */
    virtual void rcx(uint64_t val) = 0;

    /**
     * @brief Get the rdx register value
     * @return The value held by the rdx register
     */
    virtual uint64_t rdx() const = 0;
    /**
     * @brief Set the rdx register value
     * @param val The value to set
     */
    virtual void rdx(uint64_t val) = 0;

    /**
     * @brief Get the r15 register value
     * @return The value held by the r15 register
     */
    virtual uint64_t r15() const = 0;
    /**
     * @brief Set the r15 register value
     * @param val The value to set
     */
    virtual void r15(uint64_t val) = 0;

    /**
     * @brief Get the r14 register value
     * @return The value held by the r15 register
     */
    virtual uint64_t r14() const = 0;
    /**
     * @brief Set the r14 register value
     * @param val The value to set
     */
    virtual void r14(uint64_t val) = 0;

    /**
     * @brief Get the r13 register value
     * @return The value held by the r13 register
     */
    virtual uint64_t r13() const = 0;
    /**
     * @brief Set the r13 register value
     * @param val The value to set
     */
    virtual void r13(uint64_t val) = 0;

    /**
     * @brief Get the r12 register value
     * @return The value held by the r12 register
     */
    virtual uint64_t r12() const = 0;
    /**
     * @brief Set the r12 register value
     * @param val The value to set
     */
    virtual void r12(uint64_t val) = 0;

    /**
     * @brief Get the r11 register value
     * @return The value held by the r11 register
     */
    virtual uint64_t r11() const = 0;
    /**
     * @brief Set the r11 register value
     * @param val The value to set
     */
    virtual void r11(uint64_t val) = 0;

    /**
     * @brief Get the r10 register value
     * @return The value held by the r10 register
     */
    virtual uint64_t r10() const = 0;
    /**
     * @brief Set the r10 register value
     * @param val The value to set
     */
    virtual void r10(uint64_t val) = 0;

    /**
     * @brief Get the r9 register value
     * @return The value held by the r9 register
     */
    virtual uint64_t r9() const = 0;
    /**
     * @brief Set the r9 register value
     * @param val The value to set
     */
    virtual void r9(uint64_t val) = 0;

    /**
     * @brief Get the r8 register value
     * @return The value held by the r8 register
     */
    virtual uint64_t r8() const = 0;
    /**
     * @brief Set the r8 register value
     * @param val The value to set
     */
    virtual void r8(uint64_t val) = 0;

    /**
     * @brief Get the rsi register value
     * @return The value held by the rsi register
     */
    virtual uint64_t rsi() const = 0;
    /**
     * @brief Set the rsi register value
     * @param val The value to set
     */
    virtual void rsi(uint64_t val) = 0;

    /**
     * @brief Get the rdi register value
     * @return The value held by the rdi register
     */
    virtual uint64_t rdi() const = 0;
    /**
     * @brief Set the rdi register value
     * @param val The value to set
     */
    virtual void rdi(uint64_t val) = 0;

    /**
     * @brief Get the rsp register value
     * @return The value held by the rsp register
     */
    virtual uint64_t rsp() const = 0;
    /**
     * @brief Set the rsp register value
     * @param val The value to set
     */
    virtual void rsp(uint64_t val) = 0;

    /**
     * @brief Get the rbp register value
     * @return The value held by the rbp register
     */
    virtual uint64_t rbp() const = 0;
    /**
     * @brief Set the rbp register value
     * @param val The value to set
     */
    virtual void rbp(uint64_t val) = 0;

    /**
     * @brief Get the rip register value
     * @return The value held by the rip register
     */
    virtual uint64_t rip() const = 0;
    /**
     * @brief Set the rip register value
     * @param val The value to set
     */
    virtual void rip(uint64_t val) = 0;

    /**
     * @brief Get the rflags register value
     * @return The value held by the rflags register
     */
    virtual Flags& rflags() = 0;

    /**
     * @copydoc Registers::rflags()
     */
    virtual const Flags& rflags() const = 0;

    /**
     * @brief Convenience method for rflags().value(val.value())
     *
     * @param val The value to copy into this Vcpu's rflags
     */
    virtual void rflags(const Flags& val) = 0;

    /**
     * @brief Get the Efer MSR
     * @return The Efer MSR
     */
    virtual Efer efer() const = 0;

    /**
     * @brief Get a raw MSR value
     *
     * @param msr The MSR to retreive
     * @return The value held by the MSR
     * @throws CommandFailedException if the msr could not be retrieved
     */
    virtual uint64_t msr(Msr msr) const = 0;

    /**
     * @brief Set a raw MSR value
     *
     * @param msr The MSR to set
     * @param val The value to set in the MSR
     * @throws CommandFailedException if the msr could not be set
     */
    virtual void msr(Msr msr, uint64_t val) = 0;

    /**
     * @brief Get the code segment register
     *
     * @return The code segment register
     */
    virtual Segment cs() const = 0;

    /**
     * @brief Set the code segment register
     *
     * @param seg The code segment register
     */
    virtual void cs(x86::Segment seg) = 0;

    /**
     * @brief Get long mode for the current code segment
     *
     * @return true if the current code segment is in long mode
     * @return false if the current code segment is in long mode
     */
    virtual bool cs_long_mode() const = 0;

    /**
     * @brief Get the data segment register
     *
     * @return The data segment register
     */
    virtual Segment ds() const = 0;

    /**
     * @brief Get the ES register
     *
     * @return The ES register
     */
    virtual Segment es() const = 0;

    /**
     * @brief Get the FS register
     *
     * @return The FS register
     */
    virtual Segment fs() const = 0;

    /**
     * @brief Get the GS register
     *
     * @return The GS register
     */
    virtual Segment gs() const = 0;

    /**
     * @brief Get the stack segment register
     *
     * @return The stack segment register
     */
    virtual Segment ss() const = 0;

    /**
     * @brief Get the task segment register
     *
     * @return The task segment register
     */
    virtual Segment tr() const = 0;

    /**
     * @brief Get the segment descriptor for the ldt
     *
     * @return The ldt segment register
     */
    virtual Segment ldt() const = 0;

    /**
     * @brief Get control register 0
     * @return The value held by the Cr0 register
     */
    virtual Cr0 cr0() const = 0;

    /**
     * @brief Get control register 2
     * @return The value held by the Cr2 register
     */
    virtual uint64_t cr2() const = 0;

    /**
     * @brief Get control register 3
     * @return The value held by the Cr3 register
     */
    virtual uint64_t cr3() const = 0;

    /**
     * @brief Get control register 4
     * @return The value held by the Cr4 register
     */
    virtual Cr4 cr4() const = 0;

    /**
     * @brief Get control register 8
     * @return The value held by the Cr8 register
     */
    virtual uint64_t cr8() const = 0;

    /**
     * @brief Get the gdtr segment base register
     *
     * @return the gdtr segment base register
     */
    virtual uint64_t gdtr_base() const = 0;

    /**
     * @brief Get the gdtr segment limit register
     *
     * @return the gdtr segment limit register
     */
    virtual uint32_t gdtr_limit() const = 0;

    /**
     * @brief Get the interrupt descritor table base address
     *
     * @return the idtr base address
     */
    virtual uint64_t idtr_base() const = 0;

    /**
     * @brief Get the interrupt descritor table limit
     *
     * @return the idtr limit
     */
    virtual uint32_t idtr_limit() const = 0;

    /**
     * @brief Destroy the instance
     */
    virtual ~Registers() = default;
};

} // namespace x86

using Registers = x86::Registers;

} // namespace introvirt
