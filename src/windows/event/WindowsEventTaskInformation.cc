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
#include <introvirt/windows/event/WindowsEventTaskInformation.hh>

#include <introvirt/windows/kernel/nt/types/KPCR.hh>

namespace introvirt {
namespace windows {

uint64_t WindowsEventTaskInformation::pid() const { return kpcr_.pid(); }

uint64_t WindowsEventTaskInformation::tid() const { return kpcr_.tid(); }

std::string WindowsEventTaskInformation::process_name() const { return kpcr_.process_name(); }

nt::KPCR& WindowsEventTaskInformation::pcr() { return kpcr_; }

const nt::KPCR& WindowsEventTaskInformation::pcr() const { return kpcr_; }

WindowsEventTaskInformation::WindowsEventTaskInformation(nt::KPCR& kpcr) : kpcr_(kpcr) {
    kpcr_.reset();
}

WindowsEventTaskInformation::~WindowsEventTaskInformation() = default;

} // namespace windows
} // namespace introvirt