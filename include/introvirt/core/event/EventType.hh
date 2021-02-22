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

#include <ostream>
#include <string>

namespace introvirt {

/** @file */

/**
 *
 * @brief Enum describing a hypervisor event
 */
enum class EventType : int {
    EVENT_FAST_SYSCALL,     ///< A system call event
    EVENT_FAST_SYSCALL_RET, ///< A system call return event
    EVENT_SW_INT,           ///< A software interrupt event
    EVENT_SW_IRET,          ///< A software interrupt return event
    EVENT_CR_READ,          ///< A control register was read
    EVENT_CR_WRITE,         ///< A control register was written to
    EVENT_MSR_READ,         ///< An MSR was read
    EVENT_MSR_WRITE,        ///< An MSR was written to
    EVENT_EXCEPTION,        ///< An x86 exception event
    EVENT_MEM_ACCESS,       ///< Hardware assisted paging violation (memory breakpoints)
    EVENT_SINGLE_STEP,      ///< Single step event
    EVENT_HYPERCALL,        ///< An intercepted hypercall
    EVENT_REBOOT,           ///< The guest VM has rebooted
    EVENT_SHUTDOWN,         ///< The guest VM has shutdown

    EVENT_MAX = EVENT_SHUTDOWN, ///< The highest valid event type
    EVENT_UNKNOWN = -1,         ///< An unknown event
};

/**
 * @brief Get a string representation of EventType
 *
 * @param type The type to convert to string
 * @return The string representation EventType
 */
const std::string& to_string(EventType type);

/**
 * @brief Stream operator overload for EventType
 *
 * Writes the string value of the given EventType to the stream
 *
 * @param os The stream to write to
 * @param type The type to convert to a string
 * @return The stream that was passed in
 */
std::ostream& operator<<(std::ostream& os, EventType type);

} // namespace introvirt