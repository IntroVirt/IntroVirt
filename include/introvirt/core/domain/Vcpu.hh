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

#include <introvirt/core/arch/x86/Exception.hh>
#include <introvirt/core/arch/x86/Registers.hh>

#include <introvirt/core/fwd.hh>

#include <cstdint>

namespace introvirt {

/**
 * @brief A class representing a single virtual processor
 *
 * It is subclassed for specific hypervisors, such as the KvmVcpu and the
 * XenVcpu.
 */
class Vcpu {
  public:
    /**
     * @brief Get the processor's registers
     *
     * @return The registers for this Vcpu
     */
    virtual Registers& registers() = 0;

    /**
     * @copydoc Vcpu::registers()
     */
    virtual const Registers& registers() const = 0;

    /**
     * @brief Check if the processor is in long mode
     *
     * @return true if the processor is in long mode
     * @return false if the processor is not in long mode
     */
    virtual bool long_mode() const = 0;

    /**
     * @brief Check if the processor is currently in long compatibility mode
     *
     * This occurs when the processor is in 64-bit mode, but in a 32-bit code segment.
     *
     * @return true if in compatibility mode
     * @return false if not in compatibility mode
     */
    virtual bool long_compatibility_mode() const = 0;

    /**
     * @brief Pause this vcpu
     *
     * This is implemented by tracking pause count.
     * Every pause() increments the value, and resume() decrements.
     *
     * The vcpu is paused when the count goes from 0 to 1.
     * The vcpu is unpaused when the count reaches 0.
     *
     * @throws CommandFailedException If the hypervisor reports an error
     */
    virtual void pause() = 0;

    /**
     * @brief Resume this vcpu
     *
     * This is implemented by tracking pause count.
     * Every pause() increments the value, and resume() decrements.
     *
     * The vcpu is paused when the count goes from 0 to 1.
     * The vcpu is unpaused when the count reaches 0.
     *
     * @throws CommandFailedException If the hypervisor reports an error
     */
    virtual void resume() = 0;

    /**
     * @brief Toggle system call interception for this VCPU
     *
     * Enables events of type EVENT_FAST_SYSCALL and EVENT_FAST_SYSCALL_RET.
     *
     * When system call interception is enabled, SYSCALL/SYSENTER instructions are intercepted by
     * the hypervisor. If the call number matches our SystemCallFilter (or the filter is disabled),
     * a EVENT_FAST_SYSCALL event will be delivered.
     *
     * While enabled, the hypervisor also intercept all SYSRET/SYSEXIT instructions.
     *
     * @param enabled If set to true, system calls and returns that match our filters will be
     * intercepted.
     * @throws NotImplementedException if system call hooking is not supported
     * @throws CommandFailedException If the hypervisor reports an error
     */
    virtual void intercept_system_calls(bool enabled) = 0;

    /**
     * @brief Check if system call interception is enabled
     *
     * @return true if system call interception is enabled
     * @return false if system call interception is disabled
     */
    virtual bool intercept_system_calls() const = 0;

    /**
     * @brief Toggle control register write interception
     *
     * @param cr The control register to toggle interception for
     * @param enabled If set to true, writes to the given control register will be intercepted
     * @throws NotImplementedException if writes to the given CR cannot be intercepted
     * @throws CommandFailedException If the hypervisor reports an error
     */
    virtual void intercept_cr_writes(int cr, bool enabled) = 0;

    /**
     * @brief Check if writes to the control register are being intercepted
     *
     * @param cr The control register to check
     * @return true if writes to the control register are being intercepted
     * @return false if writes to the control register are not being intercepted
     */
    virtual bool intercept_cr_writes(int cr) const = 0;

    /**
     * @brief Inject an exception for this vcpu
     *
     * @param vector The exception type to inject
     * @throws CommandFailedException If the hypervisor reports an error
     */
    virtual void inject_exception(x86::Exception vector) = 0;

    /**
     * @copydoc Vcpu::inject_exception(x86::Exception)
     * @param error_code The error code to deliver
     */
    virtual void inject_exception(x86::Exception vector, int64_t error_code) = 0;

    /**
     * @copydoc Vcpu::inject_exception(x86::Exception, int64_t error_code)
     * @param cr2 The cr2 value to set (only for x86::Exception::PAGE_FAULT)
     */
    virtual void inject_exception(x86::Exception vector, int64_t error_code, uint64_t cr2) = 0;

    /**
     * @brief Inject a SYSCALL instruction into the VCPU
     *
     * You probably don't want to call this yourself.
     */
    virtual void inject_syscall() = 0;

    /**
     * @brief Inject a SYSCALL instruction into the VCPU
     *
     * You probably don't want to call this yourself.
     */
    virtual void inject_sysenter() = 0;

    /**
     * @brief Create a clone of this VCPU
     *
     * A cloned VCPU will not be able to change guest state.
     * It is mainly used when a copy is necessary for address translation.
     *
     * @return A clone of this vcpu
     */
    virtual std::unique_ptr<Vcpu> clone() const = 0;

    /**
     * @brief Check if the vcpu is currently being used by an active event
     *
     * @return true if the vcpu is currently being used to handle an event
     * @return false if the vcpu is not in an active event
     */
    virtual bool handling_event() const = 0;

    /**
     * @brief Get the system call filter for this vcpu
     *
     * This is the vcpu-level system call filter.
     *
     * If enabled, it will be checked first for a system call match.
     * If a match occurs, the event is delivered.
     *
     * If no match occurs, the domain-level filter will be checked if it is enabled.
     *
     * @return The vcpu system call filter
     */
    virtual SystemCallFilter& system_call_filter() = 0;

    /**
     * @copydoc Vcpu::system_call_filter()
     */
    virtual const SystemCallFilter& system_call_filter() const = 0;

    /**
     * @brief Get the number of this Vcpu
     *
     * @return uint32_t
     */
    virtual uint32_t id() const = 0;

    /**
     * @brief Get the domain associated with this Vcpu
     *
     * @return This Vcpu's domain
     */
    virtual Domain& domain() = 0;

    /**
     * @copydoc Vcpu::domain()
     */
    virtual const Domain& domain() const = 0;

    /**
     * @brief Get a segement descriptor given the current selector
     *
     * Check the GDT or LDT for the correct segment descriptor
     *
     * @param selector
     * @return x86::Segment
     */
    virtual x86::Segment segment(x86::SegmentSelector selector) const = 0;

    /**
     * @brief Gets the Global Descriptor Table (GDT) for this VCPU
     *
     * @return The GDT for this VCPU
     */
    virtual x86::SegmentDescriptorTable global_descriptor_table() const = 0;

    /**
     * @brief Gets the active Local Descriptor Table (LDT) for this VCPU
     *
     * @return The active LDT for this VCPU
     */
    virtual x86::SegmentDescriptorTable local_descriptor_table() const = 0;

    /**
     * @brief Gets the Interrupt Descriptor Table (IDT) for this VCPU
     *
     * @return The Idt for this VCPU
     */
    virtual std::unique_ptr<const x86::Idt> interrupt_descriptor_table() const = 0;

    /**
     * @brief Get the x86 Task State Segment (TSS)
     * @return The x86 task state segment
     */
    virtual const x86::Tss& task_state_segment() const = 0;

    /**
     * @brief Set OS-specific data for address translation
     *
     * @param data The OS-specific data to set
     */
    virtual void os_data(void* data) = 0;

    /**
     * @brief Get OS-specific data for address translation
     *
     * @return OS-specific data
     */
    virtual void* os_data() const = 0;

    /**
     * @brief Destroy the instance
     */
    virtual ~Vcpu() = default;
};

} // namespace introvirt