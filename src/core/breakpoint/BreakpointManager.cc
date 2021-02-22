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
#include "BreakpointManager.hh"
#include "core/breakpoint/BreakpointImpl.hh"
#include "core/domain/DomainImpl.hh"
#include "core/domain/VcpuImpl.hh"

#include <introvirt/core/exception/CommandFailedException.hh>
#include <introvirt/util/compiler.hh>

#include <log4cxx/logger.h>

#include <cassert>
#include <stdexcept>

namespace introvirt {

static InternalBreakpoint* HiddenBreakpoint = nullptr;
static thread_local std::shared_ptr<InternalBreakpoint> active_breakpoint = nullptr;

static log4cxx::LoggerPtr
    logger(log4cxx::Logger::getLogger("introvirt.breakpoint.BreakpointManager"));

void InternalBreakpoint::watchpoint_event(Event& event) {
    if (gpa_.value() != event.mem_access().physical_address().value()) {
        LOG4CXX_WARN(logger,
                     "Incorrect physical address: " << event.mem_access().physical_address());
    }

    if (event.mem_access().read_violation()) {

        LOG4CXX_DEBUG(logger, event.task().process_name()
                                  << ": Hiding breakpoint from guest at " << gpa_ << " RIP: 0x"
                                  << std::hex << event.vcpu().registers().rip());
    }

    if (event.mem_access().write_violation()) {
        LOG4CXX_DEBUG(logger, event.task().process_name()
                                  << ": Guest attempted to write breakpoint memory at " << gpa_);
    }

    if (*mapping_ == 0xCC && !nested_bp()) {
        disable();
        HiddenBreakpoint = this;
    }
}

void InternalBreakpoint::step_event() {
    // Re-read the original byte and then restore the breakpoint
    LOG4CXX_TRACE(logger, "Restoring breakpoint after guest memory access");
    original_byte_ = *mapping_;
    enable();
    single_step_.reset();
}

void InternalBreakpoint::deliver_breakpoint(Event& event) {
    // Get a copy of the callback set so that we don't have to hold a lock
    std::unique_lock lock(mtx_);

    std::vector<std::shared_ptr<BreakpointImplCallback>> callbacks;
    callbacks.reserve(breakpoint_list_.size());

    for (auto& weakptr : breakpoint_list_) {
        auto entry = weakptr.lock();
        if (entry)
            callbacks.push_back(entry->callback());
    }
    lock.unlock();

    LOG4CXX_DEBUG(logger, "Delivering " << callbacks.size() << " breakpoint callbacks");
    for (auto& entry : callbacks) {
        try {
            entry->deliver_event(event);
        } catch (TraceableException& ex) {
            LOG4CXX_WARN(logger, "Caught exception in deliver_breakpoint(): " << ex);
        }
    }
}

void InternalBreakpoint::add_callback(const std::shared_ptr<BreakpointImpl>& bpimpl) {
    std::unique_lock lock(mtx_);
    breakpoint_list_.push_back(bpimpl);

    if (breakpoint_list_.size() == 1) {
        enable();
    }
}

bool InternalBreakpoint::remove_expired() {
    std::unique_lock lock(mtx_);
    for (auto iter = breakpoint_list_.begin(); iter != breakpoint_list_.end();) {
        auto& weakptr = *iter;
        if (weakptr.expired()) {
            iter = breakpoint_list_.erase(iter);
        } else {
            ++iter;
        }
    }

    if (breakpoint_list_.empty()) {
        disable();
        return true;
    }

    return false;
}

InternalBreakpoint::InternalBreakpoint(const GuestAddress& address)
    : gpa_(address), mapping_(address), original_byte_(*mapping_) {

    enable();

    // Configure out watchpoint if supported
    try {
#if 0        
        auto& domain = const_cast<DomainImpl&>(static_cast<const DomainImpl&>(address.domain()));
        watchpoint_ = domain.create_watchpoint(
            address, 1, true, true, false,
            std::bind(&InternalBreakpoint::watchpoint_event, this, std::placeholders::_1));
#endif
    } catch (CommandFailedException& ex) {
        // Guest doesn't support watchpoints
        LOG4CXX_DEBUG(logger, "Failed to create watchpoint for breakpoint: " << ex.what());
    }
}

InternalBreakpoint::~InternalBreakpoint() { disable(); }

void BreakpointManager::add_ref(const std::shared_ptr<BreakpointImpl>& breakpoint) {
    std::lock_guard lock(breakpoints_.mtx_);
    if (unlikely(interrupted_))
        return;

    std::shared_ptr<InternalBreakpoint> entry;

    // See if we can find it in the breakpoint map
    const auto& address = breakpoint->address();
    auto iter = breakpoints_.map_.find(address.physical_address());
    if (iter == breakpoints_.map_.end()) {
        // Entry doesn't exist, create it
        entry = std::make_shared<InternalBreakpoint>(address);
        iter = breakpoints_.map_.emplace(address.physical_address(), std::move(entry)).first;
    } else {
        // Entry exists, try to lock it
        entry = iter->second.lock();
        if (!entry) {
            // Entry has expired, recreate it
            entry = std::make_shared<InternalBreakpoint>(address);
            iter = breakpoints_.map_.emplace(address.physical_address(), std::move(entry)).first;
        }
    }

    // Store it with the breakpoint
    breakpoint->internal_breakpoint(entry);

    // Register the breakpoint with the internal breakpoint
    entry->add_callback(breakpoint);
}

void BreakpointManager::remove_ref(BreakpointImpl& breakpoint) {
    std::lock_guard lock(breakpoints_.mtx_);
    if (unlikely(interrupted_))
        return;

    auto entry = breakpoint.internal_breakpoint();
    if (entry->remove_expired()) {
        // The internal breakpoint has no more callbacks and can be erased
        breakpoints_.map_.erase(breakpoint.address().physical_address());
    }
}

bool BreakpointManager::handle_int3_event(Event& event, bool deliver_events) {
    auto& vcpu = event.vcpu();
    auto& regs = vcpu.registers();
    GuestVirtualAddress rip(regs.rip());
    const uint64_t physical_rip = rip.physical_address();

    if (unlikely(interrupted_)) {
        return false;
    }

    // Find the breakpoint for the event
    std::unique_lock breakpoints_lock(breakpoints_.mtx_);
    LOG4CXX_DEBUG(logger, "VCPU " << vcpu.id() << ": INT3 received for " << rip);

    auto iter = breakpoints_.map_.find(physical_rip);
    if (unlikely(iter == breakpoints_.map_.end())) {
        // We don't have a breakpoint for this!
        // Check to see if there's an actual int3 instruction in place
        if (*guest_ptr<uint8_t>(rip) == 0xCC) {
            LOG4CXX_DEBUG(logger, "Injecting unwanted Int3");
            vcpu.inject_exception(x86::Exception::INT3);
            return false;
        } else {
            LOG4CXX_DEBUG(logger, "Hit unknown breakpoint. This is probably bad for the guest.")
        }
        return false;
    }

    // Get our breakpoint entry
    active_breakpoint = iter->second.lock();
    if (unlikely(!active_breakpoint)) {
        // Maybe all of our breakpoints were removed while we were waiting.
        // If that's the case, the breakpoint instruction should have already been removed.
        LOG4CXX_DEBUG(logger, "Failed to lock internal breakpoint from weak_ptr.");
        return false;
    }

    // No longer need to lock on this since we have out internal breakpoint
    breakpoints_lock.unlock();

    // Reinject the exeception if this is a nested Int3
    if (active_breakpoint->nested_bp())
        vcpu.inject_exception(x86::Exception::INT3);

    // Run callbacks
    active_breakpoint->disable();

    if (deliver_events) {
        active_breakpoint->deliver_breakpoint(event);

        if (active_breakpoint->remove_expired()) {
            // No one left waiting for this breakpoint. No need for a callback.
            LOG4CXX_TRACE(logger, "Breakpoing removed, not stepping VCPU " << vcpu.id());

            active_breakpoint.reset();
            breakpoints_lock.lock();
            breakpoints_.map_.erase(physical_rip);
            return false;
        }

        // Check if one of our callbacks changed RIP
        if (regs.rip() != rip.value()) {
            // A callback must have changed RIP, just turn the breakpoint back on
            active_breakpoint.reset();
            active_breakpoint->enable();
            LOG4CXX_TRACE(logger, "RIP changed, not stepping VCPU " << vcpu.id());
            return false;
        }
    }

    // It did not, we need to single step the guest
    LOG4CXX_DEBUG(logger, "Waiting for BP step on VCPU " << vcpu.id());
    return true;
}

void BreakpointManager::step(Event& event) {
    if (HiddenBreakpoint != nullptr) {
        // Unhide the BP
        HiddenBreakpoint->step_event();
        HiddenBreakpoint = nullptr;
    }

    // Stepping done, turn the breakpoint back on
    if (active_breakpoint != nullptr) {
        active_breakpoint->enable();
        active_breakpoint.reset();
        LOG4CXX_DEBUG(logger, "BP step on VCPU " << event.vcpu().id());
    }
}

void BreakpointManager::interrupt() {
    // Clean up and unblock any pending events
    interrupted_ = true;

    std::lock_guard lock2(breakpoints_.mtx_);

    // Disable all breakpoints
    for (auto& [address, weakptr] : breakpoints_.map_) {
        auto entry = weakptr.lock();
        if (entry)
            entry->disable();
    }
}

void BreakpointManager::start_injection() {
    if (active_breakpoint) {
        active_breakpoint->enable();
    }
}
void BreakpointManager::end_injection() {
    if (active_breakpoint) {
        active_breakpoint->disable();
    }
}

BreakpointManager::BreakpointManager() {}
BreakpointManager::~BreakpointManager() = default;

} // namespace introvirt
