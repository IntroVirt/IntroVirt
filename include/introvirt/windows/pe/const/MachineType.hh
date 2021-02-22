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

#include <cstdint>
#include <ostream>
#include <string>

namespace introvirt {
namespace windows {
namespace pe {

enum MachineType : uint16_t {
    /** x64 Platform */
    MACHINE_TYPE_X64 = 0x8664,
    /** x86 Platform */
    MACHINE_TYPE_X86 = 0x014c,
    /** Intel Itanium platform */
    MACHINE_TYPE_IA64 = 0x0200,
};

const std::string& to_string(MachineType type);
std::ostream& operator<<(std::ostream& os, MachineType type);

} // namespace pe
} // namespace windows
} // namespace introvirt