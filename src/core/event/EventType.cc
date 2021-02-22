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
#include <introvirt/core/event/EventType.hh>

namespace introvirt {

static const std::string EVENT_FAST_SYSCALL_STR("EVENT_FAST_SYSCALL");
static const std::string EVENT_FAST_SYSCALL_RET_STR("EVENT_FAST_SYSCALL_RET");
static const std::string EVENT_SW_INT_STR("EVENT_SW_INT");
static const std::string EVENT_SW_IRET_STR("EVENT_SW_IRET");
static const std::string EVENT_CR_READ_STR("EVENT_CR_READ");
static const std::string EVENT_CR_WRITE_STR("EVENT_CR_WRITE");
static const std::string EVENT_MSR_READ_STR("EVENT_MSR_READ");
static const std::string EVENT_MSR_WRITE_STR("EVENT_MSR_WRITE");
static const std::string EVENT_EXCEPTION_STR("EVENT_EXCEPTION");
static const std::string EVENT_MEM_ACCESS_STR("EVENT_MEM_ACCESS");
static const std::string EVENT_SINGLE_STEP_STR("EVENT_SINGLE_STEP");
static const std::string EVENT_HYPERCALL_STR("EVENT_HYPERCALL");
static const std::string EVENT_REBOOT_STR("EVENT_REBOOT");
static const std::string EVENT_SHUTDOWN_STR("EVENT_SHUTDOWN");
static const std::string EVENT_UNKNOWN_STR("EVENT_UNKNOWN");

const std::string& to_string(EventType type) {
    switch (type) {
    case EventType::EVENT_FAST_SYSCALL:
        return EVENT_FAST_SYSCALL_STR;
    case EventType::EVENT_FAST_SYSCALL_RET:
        return EVENT_FAST_SYSCALL_RET_STR;
    case EventType::EVENT_SW_INT:
        return EVENT_SW_INT_STR;
    case EventType::EVENT_SW_IRET:
        return EVENT_SW_IRET_STR;
    case EventType::EVENT_CR_READ:
        return EVENT_CR_READ_STR;
    case EventType::EVENT_CR_WRITE:
        return EVENT_CR_WRITE_STR;
    case EventType::EVENT_MSR_READ:
        return EVENT_MSR_READ_STR;
    case EventType::EVENT_MSR_WRITE:
        return EVENT_MSR_WRITE_STR;
    case EventType::EVENT_EXCEPTION:
        return EVENT_EXCEPTION_STR;
    case EventType::EVENT_MEM_ACCESS:
        return EVENT_MEM_ACCESS_STR;
    case EventType::EVENT_SINGLE_STEP:
        return EVENT_SINGLE_STEP_STR;
    case EventType::EVENT_HYPERCALL:
        return EVENT_HYPERCALL_STR;
    case EventType::EVENT_REBOOT:
        return EVENT_REBOOT_STR;
    case EventType::EVENT_SHUTDOWN:
        return EVENT_SHUTDOWN_STR;
    case EventType::EVENT_UNKNOWN:
        return EVENT_UNKNOWN_STR;
    }
    return EVENT_UNKNOWN_STR;
}

std::ostream& operator<<(std::ostream& os, EventType type) {
    os << to_string(type);
    return os;
}

} // namespace introvirt
