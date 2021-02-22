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
namespace x86 {

/**
 * @brief x86_64 MSR valueus
 * TODO: Many values are missing from this enum
 */
enum class Msr : uint64_t {
    MSR_EFER = 0xc0000080,           //< extended feature register
    MSR_STAR = 0xc0000081,           //< legacy mode SYSCALL target
    MSR_LSTAR = 0xc0000082,          //< long mode SYSCALL target
    MSR_CSTAR = 0xc0000083,          //< compat mode SYSCALL target
    MSR_SYSCALL_MASK = 0xc0000084,   //< EFLAGS mask for syscall
    MSR_FS_BASE = 0xc0000100,        //< 64bit FS base
    MSR_GS_BASE = 0xc0000101,        //< 64bit GS base
    MSR_KERNEL_GS_BASE = 0xc0000102, //< SwapGS GS shadow
    MSR_TSC_AUX = 0xc0000103,        //< Auxiliary TSC
    MSR_IA32_SPEC_CTRL = 0x00000048, //< Speculation Control
    MSR_IA32_PRED_CMD = 0x00000049,  //< Prediction Command

    MSR_IA32_SYSENTER_CS = 0x00000174,  //< The code segment to switch to for the SYSENTER
    MSR_IA32_SYSENTER_ESP = 0x00000175, //< The stack to switch to when using SYSENTER
    MSR_IA32_SYSENTER_EIP = 0x00000176, //< The instruction pointer to jump to when using SYSENTER
};

} // namespace x86
} // namespace introvirt