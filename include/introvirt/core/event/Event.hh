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

#include <introvirt/core/event/ControlRegisterEvent.hh>
#include <introvirt/core/event/EventTaskInformation.hh>
#include <introvirt/core/event/EventType.hh>
#include <introvirt/core/event/ExceptionEvent.hh>
#include <introvirt/core/event/MemAccessEvent.hh>
#include <introvirt/core/event/MsrAccessEvent.hh>
#include <introvirt/core/event/SystemCallEvent.hh>

#include <introvirt/core/fwd.hh>
#include <introvirt/util/json/json.hh>

#include <cstdint>
#include <functional>
#include <ostream>
#include <string>

namespace introvirt {

enum class OS { Unknown, Windows, Linux };

class EventImpl;

/**
 * @brief Inferface class for hypervisor events
 */
class Event {
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
     * @brief Get system call event information
     *
     * Valid for EVENT_FAST_SYSCALL and EVENT_FAST_SYSCALL_RET
     *
     * @return The system call event information
     * @throws InvalidMethodException if the event type is not supported
     */
    virtual SystemCallEvent& syscall() = 0;

    /**
     * @copydoc Event::syscall
     */
    virtual const SystemCallEvent& syscall() const = 0;

    /**
     * @brief Get control register access event information
     *
     * @return The control register event information
     * @throws InvalidMethodException if the event type is not supported
     */
    virtual ControlRegisterEvent& cr() = 0;

    /**
     * @copydoc Event::cr()
     */
    virtual const ControlRegisterEvent& cr() const = 0;

    /**
     * @brief Get MSR access event information
     *
     * @return The MSR event information
     * @throws InvalidMethodException if the event type is not supported
     */
    virtual MsrAccessEvent& msr() = 0;

    /**
     * @copydoc Event::msr()
     */
    virtual const MsrAccessEvent& msr() const = 0;

    /**
     * @brief Get x86 exception event information
     *
     * @return The x86 exception event information
     * @throws InvalidMethodException if the event type is not supported
     */
    virtual ExceptionEvent& exception() = 0;

    /**
     * @copydoc Event::exception()
     */
    virtual const ExceptionEvent& exception() const = 0;

    /**
     * @brief Get memory access event information
     *
     * This is implemented using HAP violations.
     * A page can be marked as any combination of R/W/X.
     * When an access occurs that is not allowed, an event is delivered.
     *
     * If the event is not handled, when the guest resumes it will just
     * fault again.
     *
     * @return The memory access event information
     * @throws InvalidMethodException if the event type is not supported
     */
    virtual MemAccessEvent& mem_access() = 0;

    /**
     * @copydoc Event::mem_access()
     */
    virtual const MemAccessEvent& mem_access() const = 0;

    /**
     * @brief Get the task information
     *
     * This is overriden by OS specific libraries (libwintrovirt) to provide task information.
     *
     * @return The task information
     * @throws InvalidMethodException if process information is not available
     */
    virtual EventTaskInformation& task() = 0;

    /**
     * @copydoc Event::task()
     */
    virtual const EventTaskInformation& task() const = 0;

    /**
     * @return the OS that this event is for
     */
    virtual OS os_type() const = 0;

    /**
     * @brief Serialize the event into JSON
     * @return A JSON representation of this Event
     */
    virtual Json::Value json() const = 0;

    /**
     * @brief Get the unique identifier for this event
     */
    virtual uint64_t id() const = 0;

    /**
     * @brief Used internally
     *
     * @return EventImpl&
     */
    virtual EventImpl& impl() = 0;

    /**
     * @brief Destroy the instance
     */
    virtual ~Event() = default;
};

const std::string& to_string(OS);
std::ostream& operator<<(std::ostream&, OS);

} // namespace introvirt