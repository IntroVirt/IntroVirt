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

namespace introvirt {
namespace windows {
namespace ws2_32 {

typedef uint64_t SOCKET;
static constexpr SOCKET INVALID_SOCKET = ~0ull;

// This isn't actually a type, some functions can return it.
// We need socket error codes somewhere I guess.
static constexpr int32_t SOCKET_ERROR = -1;

} // namespace ws2_32
} // namespace windows
} // namespace introvirt