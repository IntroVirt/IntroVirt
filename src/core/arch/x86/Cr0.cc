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

#include <introvirt/core/arch/x86/Cr0.hh>

namespace introvirt {
namespace x86 {

constexpr static uint32_t CR0_PE = (1u << 0);
constexpr static uint32_t CR0_MP = (1u << 1);
constexpr static uint32_t CR0_EM = (1u << 2);
constexpr static uint32_t CR0_TS = (1u << 4);
constexpr static uint32_t CR0_ET = (1u << 4);
constexpr static uint32_t CR0_NE = (1u << 5);
constexpr static uint32_t CR0_WP = (1u << 16);
constexpr static uint32_t CR0_AM = (1u << 18);
constexpr static uint32_t CR0_NW = (1u << 29);
constexpr static uint32_t CR0_CD = (1u << 30);
constexpr static uint32_t CR0_PG = (1u << 31);

bool Cr0::pe() const { return cr0_ & CR0_PE; }
bool Cr0::mp() const { return cr0_ & CR0_MP; }
bool Cr0::em() const { return cr0_ & CR0_EM; }
bool Cr0::ts() const { return cr0_ & CR0_TS; }
bool Cr0::et() const { return cr0_ & CR0_ET; }
bool Cr0::ne() const { return cr0_ & CR0_NE; }
bool Cr0::wp() const { return cr0_ & CR0_WP; }
bool Cr0::am() const { return cr0_ & CR0_AM; }
bool Cr0::nw() const { return cr0_ & CR0_NW; }
bool Cr0::cd() const { return cr0_ & CR0_CD; }
bool Cr0::pg() const { return cr0_ & CR0_PG; }
uint64_t Cr0::value() const { return cr0_; }
Cr0::Cr0(uint64_t cr0) : cr0_(cr0) {}

} // namespace x86
} // namespace introvirt