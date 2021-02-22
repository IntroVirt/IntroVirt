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
#include <string>

namespace introvirt {
namespace windows {
namespace condrv {

enum class ConsoleRequestIoctl : uint32_t {
    ConsoleCallServerGeneric = 0x500016,
    ConsoleCommitState = 0x500023,
    ConsoleLaunchServerProcess = 0x500037,

    Unknown = 0xFFFFFFFF,
};

/**
 * Convert the enum value to a string
 */
const std::string& to_string(ConsoleRequestIoctl);

} /* namespace condrv */
} /* namespace windows */
} /* namespace introvirt */