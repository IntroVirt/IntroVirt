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

#include <introvirt/core/domain/Guest.hh>

#include <memory>

namespace introvirt {

class Event;
class HypervisorEvent;

enum class GuestPageFaultResult { PTE_FIXED, RETRY, FAILURE };

class GuestImpl {
  public:
    /**
     * @brief Handler function for allowing the IGuest to process an event
     *
     * This is the callback for the IGuest instance to convert the "raw" event
     * into one with specific OS information.
     *
     * @param event The incoming event
     * @return The OS-specific event
     */
    virtual std::unique_ptr<Event> filter_event(std::unique_ptr<HypervisorEvent>&& event) = 0;

    /**
     * @brief Called when the normal page fault handler can't handle a fault
     *
     * @param gva The faulting address
     * @param pte The not-present PTE
     * @return The result of the function call
     */
    virtual GuestPageFaultResult handle_page_fault(const GuestVirtualAddress& gva,
                                                   uint64_t& pte) const = 0;

    /**
     * @brief Get the current thread id for the given vcpu
     *
     * @param vcpu The vcpu to check
     * @return uint64_t indicating the unique ID of the current thread
     */
    virtual uint64_t get_current_thread_id(const Vcpu& vcpu) const = 0;
};

} // namespace introvirt