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

#include <introvirt/core/arch/x86/Flags.hh>

namespace introvirt {
namespace x86 {

constexpr static uint32_t FLAGS_CF_MASK = 0x000001;
constexpr static uint32_t FLAGS_PF_MASK = 0x000004;
constexpr static uint32_t FLAGS_AF_MASK = 0x000010;
constexpr static uint32_t FLAGS_ZF_MASK = 0x000040;
constexpr static uint32_t FLAGS_SF_MASK = 0x000080;
constexpr static uint32_t FLAGS_TF_MASK = 0x000100;
constexpr static uint32_t FLAGS_IF_MASK = 0x000200;
constexpr static uint32_t FLAGS_DF_MASK = 0x000400;
constexpr static uint32_t FLAGS_OF_MASK = 0x000800;
constexpr static uint32_t FLAGS_IOPL_MASK = 0x003000;
constexpr static uint32_t FLAGS_IOPL_SHIFT = 12;
constexpr static uint32_t FLAGS_NT_MASK = 0x004000;
constexpr static uint32_t FLAGS_RF_MASK = 0x010000;
constexpr static uint32_t FLAGS_VM_MASK = 0x020000;
constexpr static uint32_t FLAGS_AC_MASK = 0x040000;
constexpr static uint32_t FLAGS_VIF_MASK = 0x080000;
constexpr static uint32_t FLAGS_VIP_MASK = 0x100000;
constexpr static uint32_t FLAGS_ID_MASK = 0x200000;

bool Flags::carry() const { return *flags_ & FLAGS_CF_MASK; }
bool Flags::parity() const { return *flags_ & FLAGS_PF_MASK; }
bool Flags::adjust() const { return *flags_ & FLAGS_AF_MASK; }
bool Flags::zero() const { return *flags_ & FLAGS_ZF_MASK; }
bool Flags::sign() const { return *flags_ & FLAGS_SF_MASK; }
bool Flags::trap() const { return *flags_ & FLAGS_TF_MASK; }
bool Flags::interrupt() const { return *flags_ & FLAGS_IF_MASK; }
void Flags::interrupt(bool val) {
    if (val)
        value(*flags_ | FLAGS_IF_MASK);
    else
        value(*flags_ & ~FLAGS_IF_MASK);
}

bool Flags::direction() const { return *flags_ & FLAGS_DF_MASK; }
bool Flags::overflow() const { return *flags_ & FLAGS_OF_MASK; }
int8_t Flags::iopl() const { return (*flags_ & FLAGS_IOPL_MASK) >> FLAGS_IOPL_SHIFT; }
bool Flags::nested_task() const { return *flags_ & FLAGS_NT_MASK; }
bool Flags::resume() const { return *flags_ & FLAGS_RF_MASK; }
bool Flags::virtual_8086() const { return *flags_ & FLAGS_VM_MASK; }
bool Flags::alignment_check() const { return *flags_ & FLAGS_AC_MASK; }
bool Flags::virtual_interrupt() const { return *flags_ & FLAGS_VIF_MASK; }
bool Flags::virtual_interrupt_pending() const { return *flags_ & FLAGS_VIP_MASK; }
bool Flags::cpuid() const { return *flags_ & FLAGS_ID_MASK; }

void Flags::value(uint64_t value) {
    *flags_ = value;
    set_modified();
}
uint64_t Flags::value() const { return *flags_; }

Flags::Flags() : value_(0), flags_(&value_) {}
Flags::Flags(uint64_t flags) : value_(flags), flags_(&value_) {}
Flags::Flags(uint64_t& flags, bool* modified) : flags_(&flags), modified_(modified) {}

} // namespace x86
} // namespace introvirt