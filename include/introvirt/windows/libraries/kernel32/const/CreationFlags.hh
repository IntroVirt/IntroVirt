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

namespace introvirt {
namespace windows {
namespace kernel32 {

/**
 * @brief Used by CreateProcessA's dwCreationFlags argument
 */
enum CreationFlags {
    CREATE_SUSPENDED = 0x4,
    CREATE_NEW_CONSOLE = 0x10,
    CREATE_UNICODE_ENVIRONMENT = 0x00000400,
    CREATE_NO_WINDOW = 0x08000000,

    /* These are valid too, but defined in PRIORITY_CLASS */
    // BELOW_NORMAL_PRIORITY_CLASS = 0x00004000,
    // NORMAL_PRIORITY_CLASS = 0x00000020,
    // ABOVE_NORMAL_PRIORITY_CLASS = 0x00008000,
    // HIGH_PRIORITY_CLASS = 0x00000080,
    // REALTIME_PRIORITY_CLASS = 0x00000100,
};

} // namespace kernel32
} // namespace windows
} // namespace introvirt