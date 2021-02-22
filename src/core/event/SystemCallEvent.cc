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
#include <introvirt/core/event/SystemCallEvent.hh>

namespace introvirt {

static const std::string FASTCALL_SYSCALL_STR("FASTCALL_SYSCALL");
static const std::string FASTCALL_SYSRET_STR("FASTCALL_SYSRET");
static const std::string FASTCALL_SYSENTER_STR("FASTCALL_SYSENTER");
static const std::string FASTCALL_SYSEXIT_STR("FASTCALL_SYSEXIT");
static const std::string FASTCALL_UNKNOWN_STR("FASTCALL_UNKNOWN");

const std::string& to_string(FastCallType type) {

    switch (type) {
    case FastCallType::FASTCALL_SYSCALL:
        return FASTCALL_SYSCALL_STR;
    case FastCallType::FASTCALL_SYSRET:
        return FASTCALL_SYSRET_STR;
    case FastCallType::FASTCALL_SYSENTER:
        return FASTCALL_SYSENTER_STR;
    case FastCallType::FASTCALL_SYSEXIT:
        return FASTCALL_SYSEXIT_STR;
    case FastCallType::FASTCALL_UNKNOWN:
        return FASTCALL_UNKNOWN_STR;
    }

    return FASTCALL_UNKNOWN_STR;
}

std::ostream& operator<<(std::ostream& os, FastCallType type) {
    os << to_string(type);
    return os;
}

} // namespace introvirt