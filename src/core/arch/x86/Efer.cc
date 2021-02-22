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

#include <introvirt/core/arch/x86/Efer.hh>

namespace introvirt {
namespace x86 {

constexpr static uint64_t EFER_SCE = (1u << 0);
constexpr static uint64_t EFER_LME = (1u << 8);
constexpr static uint64_t EFER_LMA = (1u << 10);
constexpr static uint64_t EFER_NXE = (1u << 11);
constexpr static uint64_t EFER_SVME = (1u << 12);
constexpr static uint64_t EFER_LMSLE = (1u << 13);
constexpr static uint64_t EFER_FFXSR = (1u << 14);
constexpr static uint64_t EFER_TCE = (1u << 15);

bool Efer::sce() const { return efer_ & EFER_SCE; }
bool Efer::lme() const { return efer_ & EFER_LME; }
bool Efer::lma() const { return efer_ & EFER_LMA; }
bool Efer::nxe() const { return efer_ & EFER_NXE; }
bool Efer::svme() const { return efer_ & EFER_SVME; }
bool Efer::lmsle() const { return efer_ & EFER_LMSLE; }
bool Efer::ffxsr() const { return efer_ & EFER_FFXSR; }
bool Efer::tce() const { return efer_ & EFER_TCE; }
uint64_t Efer::value() const { return efer_; }

} // namespace x86
} // namespace introvirt