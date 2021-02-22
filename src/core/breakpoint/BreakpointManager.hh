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

#include <introvirt/core/breakpoint/SingleStep.hh>
#include <introvirt/core/breakpoint/Watchpoint.hh>

#include <introvirt/core/memory/guest_ptr.hh>

#include <atomic>
#include <list>
#include <memory>
#include <mutex>
#include <set>
#include <unordered_map>

namespace introvirt {

class BreakpointImpl;
class DomainImpl;

/**
 * @brief This is the low-level breakpoint class
 *
 */
class InternalBreakpoint final {
  public:
    /**
     * @brief Insert the Int3 breakpoint
     */
    void enable() { *mapping_ = 0xCC; }

    /**
     * @brief Restore the original instruction
     */
    void disable() { *mapping_ = original_byte_; }

    /**
     * @brief Check if the guest already had a breakpoint instruction at the target address
     */
    bool nested_bp() const { return original_byte_ == 0xCC; }

    void watchpoint_event(Event& event);
    void step_event();

    void deliver_breakpoint(Event& event);

    void add_callback(const std::shared_ptr<BreakpointImpl>& bpimpl);
    bool remove_expired();

    InternalBreakpoint(const GuestAddress& address);
    ~InternalBreakpoint();

  private:
    GuestPhysicalAddress gpa_;
    guest_ptr<uint8_t> mapping_;
    std::unique_ptr<Watchpoint> watchpoint_;
    std::unique_ptr<SingleStep> single_step_;
    uint8_t original_byte_;

    std::list<std::weak_ptr<BreakpointImpl>> breakpoint_list_;
    std::recursive_mutex mtx_;
};

/**
 * @brief Internal class for managing low-level breakpoints
 *
 */
class BreakpointManager final {
  public:
    bool handle_int3_event(Event& event, bool deliver_events);
    void step(Event& event);

    void interrupt();

    void add_ref(const std::shared_ptr<BreakpointImpl>& breakpoint);
    void remove_ref(BreakpointImpl& breakpoint);

    void start_injection();
    void end_injection();

    BreakpointManager();
    ~BreakpointManager();

  private:
    struct {
        std::recursive_mutex mtx_;
        std::unordered_map<uint64_t, std::weak_ptr<InternalBreakpoint>> map_;
    } breakpoints_;

    std::atomic_bool interrupted_ = {false};
};

} // namespace introvirt