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

#include <introvirt/core/arch/x86/Cr4.hh>

namespace introvirt {
namespace x86 {

static constexpr uint64_t CR4_VME = (1 << 0);
static constexpr uint64_t CR4_PVI = (1 << 1);
static constexpr uint64_t CR4_TSD = (1 << 2);
static constexpr uint64_t CR4_DE = (1 << 3);
static constexpr uint64_t CR4_PSE = (1 << 4);
static constexpr uint64_t CR4_PAE = (1 << 5);
static constexpr uint64_t CR4_MCE = (1 << 6);
static constexpr uint64_t CR4_PGE = (1 << 7);
static constexpr uint64_t CR4_PCE = (1 << 8);
static constexpr uint64_t CR4_OSFXSR = (1 << 9);
static constexpr uint64_t CR4_OSXMMEXCPT = (1 << 10);
static constexpr uint64_t CR4_UMIP = (1 << 11);
static constexpr uint64_t CR4_LA57 = (1 << 12);
static constexpr uint64_t CR4_VMXE = (1 << 13);
static constexpr uint64_t CR4_SMXE = (1 << 14);
static constexpr uint64_t CR4_FSGSBASE = (1 << 16);
static constexpr uint64_t CR4_PCIDE = (1 << 17);
static constexpr uint64_t CR4_OSXSAVE = (1 << 18);
static constexpr uint64_t CR4_SMEP = (1 << 20);
static constexpr uint64_t CR4_SMAP = (1 << 21);
static constexpr uint64_t CR4_PKE = (1 << 22);

bool Cr4::vme() const { return cr4_ & CR4_VME; }
bool Cr4::pvi() const { return cr4_ & CR4_PVI; }
bool Cr4::tsd() const { return cr4_ & CR4_TSD; }
bool Cr4::de() const { return cr4_ & CR4_DE; }
bool Cr4::pse() const { return cr4_ & CR4_PSE; }
bool Cr4::pae() const { return cr4_ & CR4_PAE; }
bool Cr4::mce() const { return cr4_ & CR4_MCE; }
bool Cr4::pge() const { return cr4_ & CR4_PGE; }
bool Cr4::pce() const { return cr4_ & CR4_PCE; }
bool Cr4::osfxsr() const { return cr4_ & CR4_OSFXSR; }
bool Cr4::osxmmexcpt() const { return cr4_ & CR4_OSXMMEXCPT; }
bool Cr4::umip() const { return cr4_ & CR4_UMIP; }
bool Cr4::la57() const { return cr4_ & CR4_LA57; }
bool Cr4::vmxe() const { return cr4_ & CR4_VMXE; }
bool Cr4::smxe() const { return cr4_ & CR4_SMXE; }
bool Cr4::fsgsbase() const { return cr4_ & CR4_FSGSBASE; }
bool Cr4::pcide() const { return cr4_ & CR4_PCIDE; }
bool Cr4::osxsave() const { return cr4_ & CR4_OSXSAVE; }
bool Cr4::smep() const { return cr4_ & CR4_SMEP; }
bool Cr4::smap() const { return cr4_ & CR4_SMAP; }
bool Cr4::pke() const { return cr4_ & CR4_PKE; }
uint64_t Cr4::value() const { return cr4_; }

Cr4::Cr4(uint64_t cr4) : cr4_(cr4) {}

} // namespace x86
} // namespace introvirt