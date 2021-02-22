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
namespace pe {

enum UNWIND_FLAGS {
    UNW_FLAG_NHANDLER = 0x0,
    UNW_FLAG_EHANDLER = 0x1,
    UNW_FLAG_UHANDLER = 0x2,
    UNW_FLAG_CHAININFO = 0x4
};

} // namespace pe
} // namespace windows
} // namespace introvirt