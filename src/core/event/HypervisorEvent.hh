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
#include <introvirt/core/event/Event.hh>
#include <introvirt/core/event/EventType.hh>
#include <introvirt/core/event/SystemCallEvent.hh>
#include <introvirt/core/fwd.hh>
#include <introvirt/core/memory/GuestPhysicalAddress.hh>

namespace introvirt {

class HypervisorEvent {
  public:
    /**
     * @brief Get the Vcpu that triggered the event
     *
     * @return The Vcpu that triggered the event
     */
    virtual Vcpu& vcpu() = 0;

    /**
     * @copydoc Event::vcpu()
     */
    virtual const Vcpu& vcpu() const = 0;

    /**
     * @brief Get the Domain that the event is for
     *
     * @return The domain that the event is for
     */
    virtual Domain& domain() = 0;

    /**
     * @copydoc Event::domain()
     *
     * @return const Domain&
     */
    virtual const Domain& domain() const = 0;

    /**
     * @brief Get the type of event
     *
     * @return EventType
     */
    virtual EventType type() const = 0;

    /**
     * @brief Get the type of system call or return instruction being executed
     *
     * This can be used to check if the call was SYSCALL/SYSENTER or SYSRET/SYSEXIT.
     *
     * Only valid for EventType::EVENT_FAST_SYSCALL and EventType::EVENT_FAST_SYSCALL_RET
     *
     * @return FastCallType
     */
    virtual FastCallType system_call_type() const = 0;

    /**
     * @brief Get the address of the system call return
     *
     * @return uint64_t
     */
    virtual uint64_t syscall_return_address() const = 0;

    /**
     * Get the number of the control register being accessed
     *
     * Only valid for EventType::EVENT_CR_READ and EventType::EVENT_CR_WRITE
     *
     * @return The control register that has been accessed
     */
    virtual int control_register() const = 0;

    /**
     * @brief Get the value of the control register
     *
     * Only valid for EventType::EVENT_CR_READ and EventType::EVENT_CR_WRITE
     *
     * @return The value of the new CR value on WRITE, or the returned value on READ
     */
    virtual uint64_t control_register_value() const = 0;

    /**
     * Get the number of the Ms register being accessed
     *
     * Only valid for EventType::EVENT_MSR_READ and EventType::EVENT_MSR_WRITE
     *
     * @return The control register that has been accessed
     */
    virtual uint64_t msr_index() const = 0;

    /**
     * @brief Get the value of the control register
     *
     * Only valid for EventType::EVENT_MSR_READ and EventType::EVENT_MSR_WRITE
     *
     * @return The value of the new MSR value on WRITE, or the returned value on READ
     */
    virtual uint64_t msr_value() const = 0;

    /**
     * @brief Get the vector of the exception that was intercepted
     *
     * Only valid for EventType::EVENT_EXCEPTION
     *
     * @return The exception type associated with this event
     */
    virtual x86::Exception exception() const = 0;

    /**
     * @brief Get the faulting guest physical address
     *
     * Only value for EventType::EVENT_MEM_ACCESS
     *
     * @return The faulting guest physical address
     */
    virtual GuestPhysicalAddress mem_access_physical_address() const = 0;

    /**
     * @brief Returns true if the event was caused by a read attempt
     *
     * Only value for EventType::EVENT_MEM_ACCESS
     *
     * @return True if the fault was caused by a read attempt
     */
    virtual bool mem_access_read() const = 0;

    /**
     * @brief Returns true if the event was caused by a write attempt
     *
     * Only value for EventType::EVENT_MEM_ACCESS
     *
     * @return True if the fault was caused by a write attempt
     */
    virtual bool mem_access_write() const = 0;

    /**
     * @brief Returns true if the event was caused by an execute attempt
     *
     * Only value for EventType::EVENT_MEM_ACCESS
     *
     * @return True if the fault was caused by an execute attempt
     */
    virtual bool mem_access_execute() const = 0;

    /**
     * @brief Discard this event.
     *
     * Used for handling suspended events.
     *
     * Don't call this normally. It's for internal usage.
     */
    virtual void discard(bool value) = 0;

    /**
     * @brief Get the unique identifier for this event
     */
    virtual uint64_t id() const = 0;

    virtual ~HypervisorEvent() = default;
};

} // namespace introvirt