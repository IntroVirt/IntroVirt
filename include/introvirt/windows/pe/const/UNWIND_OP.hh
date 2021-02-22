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

enum UNWIND_OP {
    UWOP_PUSH_NONVOL = 0,     /* info == register number */
    UWOP_ALLOC_LARGE = 1,     /* no info, alloc size in next 2 slots */
    UWOP_ALLOC_SMALL = 2,     /* info == size of allocation / 8 - 1 */
    UWOP_SET_FPREG = 3,       /* no info, FP = RSP + UnwindInfo.FPRegOffset*16 */
    UWOP_SAVE_NONVOL = 4,     /* info == register number, offset in next slot */
    UWOP_SAVE_NONVOL_FAR = 5, /* info == register number, offset in next 2 slots */
    UWOP_SAVE_XMM = 6,
    UWOP_SAVE_XMM_FAR = 7,
    UWOP_SAVE_XMM128 = 8,     /* info == XMM reg number, offset in next slot */
    UWOP_SAVE_XMM128_FAR = 9, /* info == XMM reg number, offset in next 2 slots */
    UWOP_PUSH_MACHFRAME = 10, /* info == 0: no error-code, 1: error-code */
};

} // namespace pe
} // namespace windows
} // namespace introvirt