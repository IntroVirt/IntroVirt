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
#include "LUID_IMPL.hh"

#include <introvirt/core/memory/guest_ptr.hh>
#include <introvirt/windows/kernel/nt/types/LUID.hh>

namespace introvirt {
namespace windows {
namespace nt {

uint64_t LUID_IMPL::value() const { return luid_->Value; }
void LUID_IMPL::value(uint64_t value) { luid_->Value = value; }

uint32_t LUID_IMPL::LowPart() const { return luid_->LowPart; }
void LUID_IMPL::LowPart(uint32_t lowPart) { luid_->LowPart = lowPart; }

int32_t LUID_IMPL::HighPart() const { return luid_->HighPart; }
void LUID_IMPL::HighPart(int32_t highPart) { luid_->HighPart = highPart; }

LUID_IMPL::LUID_IMPL(const GuestVirtualAddress& gva) : luid_(gva) {}

} /* namespace nt */
} /* namespace windows */
} /* namespace introvirt */
