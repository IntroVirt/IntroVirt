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
namespace crypt32 {

enum CRYPTPROTECT_FLAG {
    CRYPTPROTECT_UI_FORBIDDEN = 0x1,
    CRYPTPROTECT_LOCAL_MACHINE = 0x4,
    CRYPTPROTECT_CRED_SYNC = 0x8,
    CRYPTPROTECT_AUDIT = 0x10,
    CRYPTPROTECT_VERIFY_PROTECTION = 0x40,
    CRYPTPROTECT_CRED_REGENERATE = 0x80,
    CRYPTPROTECT_SYSTEM = 0x20000000
};

}
} // namespace windows
} // namespace introvirt