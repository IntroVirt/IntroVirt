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

#include <introvirt/core/exception/TraceableException.hh>
#include <introvirt/windows/kernel/nt/types/KPCR.hh>

namespace introvirt {
namespace windows {

// Return the values SNAPSHOTTED at construction (see the header); re-reading
// kpcr_ here would race the shared per-vcpu KPCR -> stale-pointer SIGSEGV.
uint64_t WindowsEventTaskInformation::pid() const { return pid_; }

uint64_t WindowsEventTaskInformation::tid() const { return tid_; }

std::string WindowsEventTaskInformation::process_name() const { return process_name_; }

nt::KPCR& WindowsEventTaskInformation::pcr() { return kpcr_; }

const nt::KPCR& WindowsEventTaskInformation::pcr() const { return kpcr_; }

WindowsEventTaskInformation::WindowsEventTaskInformation(nt::KPCR& kpcr) : kpcr_(kpcr) {
    // Built by the poller right after in_event_=true, so registers/KPCR are valid
    // here. Resolve the current thread once and snapshot the ids so later
    // accessors never re-read the shared, racy kpcr_.
    kpcr_.reset();
    try {
        pid_ = kpcr_.pid();
        tid_ = kpcr_.tid();
        process_name_ = kpcr_.process_name();
    } catch (const TraceableException&) {
        // degraded KPCR (KPTI non-canonical thread ptr) -> leave defaults
    }
}

WindowsEventTaskInformation::~WindowsEventTaskInformation() = default;

} // namespace windows
} // namespace introvirt