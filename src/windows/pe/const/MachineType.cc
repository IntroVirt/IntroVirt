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
#include <introvirt/windows/pe/const/MachineType.hh>

namespace introvirt {
namespace windows {
namespace pe {

const std::string& to_string(MachineType type) {
    static const std::string MACHINE_TYPE_X64_STR("MACHINE_TYPE_X64");
    static const std::string MACHINE_TYPE_X86_STR("MACHINE_TYPE_X86");
    static const std::string MACHINE_TYPE_IA64_STR("MACHINE_TYPE_IA64");
    static const std::string MACHINE_TYPE_UNKNOWN_STR("MACHINE_TYPE_UNKNOWN");

    switch (type) {
    case MachineType::MACHINE_TYPE_X64:
        return MACHINE_TYPE_X64_STR;
    case MachineType::MACHINE_TYPE_X86:
        return MACHINE_TYPE_X86_STR;
    case MachineType::MACHINE_TYPE_IA64:
        return MACHINE_TYPE_IA64_STR;
    }

    return MACHINE_TYPE_UNKNOWN_STR;
}

std::ostream& operator<<(std::ostream& os, MachineType type) {
    os << to_string(type);
    return os;
}

} // namespace pe
} // namespace windows
} // namespace introvirt