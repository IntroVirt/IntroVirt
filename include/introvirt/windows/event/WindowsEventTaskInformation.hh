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

#include <introvirt/core/event/EventTaskInformation.hh>
#include <introvirt/windows/kernel/nt/fwd.hh>

namespace introvirt {
namespace windows {

class WindowsEventTaskInformation final : public EventTaskInformation {
  public:
    uint64_t pid() const override;

    uint64_t tid() const override;

    std::string process_name() const override;

    /**
     * @brief Get the Processor Control Region
     *
     * Get the kernel PCR for the current event.
     *
     * @return The KPCR class for the event's vcpu
     */
    nt::KPCR& pcr();

    /**
     * @copydoc WindowsEventTaskInformation::pcr()
     */
    const nt::KPCR& pcr() const;

    WindowsEventTaskInformation(nt::KPCR& kpcr);

    ~WindowsEventTaskInformation();

  private:
    nt::KPCR& kpcr_;
    // SECTEPE: pid/tid/process_name SNAPSHOTTED at construction (while the vcpu
    // is in its event and registers are valid). kpcr_ is a shared per-vcpu object
    // that later events reset() to their current thread; re-reading it later
    // (e.g. from end_injection) reads a stale/wrong current-thread pointer ->
    // non-canonical deref -> SIGSEGV. The event's task is the thread that
    // generated it, so the snapshot is also more correct.
    uint64_t pid_ = 0;
    uint64_t tid_ = 0;
    std::string process_name_;
};

} // namespace windows
} // namespace introvirt