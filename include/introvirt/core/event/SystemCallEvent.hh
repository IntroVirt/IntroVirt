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

#include <introvirt/core/fwd.hh>

#include <introvirt/core/memory/GuestVirtualAddress.hh>

#include <cstdint>
#include <string>

namespace introvirt {

/**
 * @brief Enum class describing the type of fast system call
 */
enum class FastCallType {
    FASTCALL_SYSCALL,
    FASTCALL_SYSRET,
    FASTCALL_SYSENTER,
    FASTCALL_SYSEXIT,
    FASTCALL_UNKNOWN
};

class SystemCallEventImpl;

/**
 * @brief Interface for system call events
 *
 * Methods related to fast system call events.
 * This only applies to SYSCALL/SYSRET and SYSENTER/SYSEXIT.
 *
 * Software interrupt based system calls are not yet handled.
 */
class SystemCallEvent {
  public:
    /**
     * @brief Get the type of fast system call instruction
     *
     * @return The type of instruction that was executed to perform a fast system call (or return)
     */
    virtual FastCallType instruction() const = 0;

    /**
     * @brief Gets the associated system call handler with this event
     *
     * This is set by the OS library (i.e., libwintrovirt).
     * It can return nullptr if the underlying system call is not supported.
     *
     * @return The system call handler, or nullptr if the call is unsupported.
     */
    virtual SystemCall* handler() = 0;

    /**
     * @copydoc SystemCallEvent::handler()
     */
    virtual const SystemCall* handler() const = 0;

    /**
     * @brief Get a string represenatation of the system call name
     */
    virtual std::string name() const = 0;

    /**
     * @brief Get the system call number executed.
     *
     * @return The value of the RAX register when the system call was executed
     */
    virtual uint64_t raw_index() const = 0;

    /**
     * @brief Instruct that the system call's return should be hooked
     *
     * @param enabled If true, the return of this event will be hooked
     */
    virtual void hook_return(bool enabled) = 0;

    /**
     * @brief Check if the return is set to be hooked
     *
     * @return True if hook_return is set
     */
    virtual bool hook_return() const = 0;

    /**
     * @brief Get the address where the system call will return
     *
     * @return GuestVirtualAddress
     */
    virtual uint64_t return_address() const = 0;

    /**
     * @brief Used internally
     */
    virtual SystemCallEventImpl& impl() = 0;

    /**
     * @brief Destroy the instance
     */
    virtual ~SystemCallEvent() = default;

  protected:
    SystemCallEvent() = default;
};

/**
 * @brief Get a string representation of FastCallType
 *
 * @param type The type to convert to string
 * @return The string representation FastCallType
 */
const std::string& to_string(FastCallType type);

/**
 * @brief Stream operator overload for FastCallType
 *
 * Writes the string value of the given FastCallType to the stream
 *
 * @param os The stream to write to
 * @param type The type to convert to a string
 * @return The stream that was passed in
 */
std::ostream& operator<<(std::ostream& os, FastCallType type);

} // namespace introvirt