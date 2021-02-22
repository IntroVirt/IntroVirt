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
#include "WatchpointManager.hh"
#include "WatchpointImpl.hh"

#include "core/domain/DomainImpl.hh"
#include "core/domain/VcpuImpl.hh"

#include <introvirt/util/compiler.hh>

#include <log4cxx/logger.h>

#include <cassert>

namespace introvirt {

static thread_local std::set<WatchpointMapEntry*> SteppingWatchpoints;
static thread_local std::set<WatchpointImpl*> SteppingDelivered;

static log4cxx::LoggerPtr
    logger(log4cxx::Logger::getLogger("introvirt.breakpoint.WatchpointManager"));

void InternalWatchpoint::enable() {
    enabled_ = true;
    update();
}
void InternalWatchpoint::disable() {
    enabled_ = false;
    update();
}

bool InternalWatchpoint::read() const { return read_; }
void InternalWatchpoint::read(bool val) { read_ = val; }

bool InternalWatchpoint::write() const { return write_; }
void InternalWatchpoint::write(bool val) { write_ = val; }

bool InternalWatchpoint::execute() const { return execute_; }
void InternalWatchpoint::execute(bool val) { execute_ = val; }

void InternalWatchpoint::update() {
    if (enabled_) {
        if (read_ != current_read_ || write_ != current_write_ || execute_ != current_execute_) {
            domain_.intercept_mem_access(gfn_, read_, read_ || write_, execute_);
            current_read_ = read_;
            current_write_ = write_;
            current_execute_ = execute_;
        }
    } else {
        domain_.intercept_mem_access(gfn_, false, false, false);
        current_read_ = false;
        current_write_ = false;
        current_execute_ = false;
    }
}

InternalWatchpoint::InternalWatchpoint(DomainImpl& domain, uint64_t gfn)
    : domain_(domain), gfn_(gfn) {}

InternalWatchpoint::~InternalWatchpoint() { disable(); }

void WatchpointManager::interrupt() {
    // Clean up and unblock any pending events
    interrupted_ = true;

    std::lock_guard lock2(watchpoints_.mtx_);

    // Disable all breakpoints
    watchpoints_.map_.clear();

    if (stepping_active_) {
        SteppingWatchpoints.clear();
        SteppingDelivered.clear();
        stepping_active_ = false;
    }
}

inline static uint64_t round_to_page_size(uint32_t value) {
    // Round address up to page size, only works if PAGE_SIZE is a power of 2
    return (value + x86::PageDirectory::PAGE_SIZE - 1) & -x86::PageDirectory::PAGE_SIZE;
}

void WatchpointManager::add_ref(WatchpointImpl& watchpoint) {
    auto& domain = static_cast<DomainImpl&>(const_cast<Domain&>(watchpoint.address().domain()));

    auto end_address = watchpoint.address().clone();
    *end_address += (watchpoint.length() - 1);
    const auto end_page = end_address->page_number();

    std::lock_guard<decltype(watchpoints_.mtx_)> watchpoint_lock(watchpoints_.mtx_);

    if (unlikely(interrupted_))
        return;

    for (auto address = watchpoint.address().clone(); address->page_number() <= end_page;
         *address += x86::PageDirectory::PAGE_SIZE) {
        GuestPhysicalAddress physical_address(*address);
        const uint64_t gfn = physical_address.page_number();
        auto iter = watchpoints_.map_.find(gfn);
        if (iter == watchpoints_.map_.end()) {
            // Create it
            LOG4CXX_DEBUG(logger, "Adding watchpoint for gfn 0x" << std::hex << gfn);
            auto entry = std::make_unique<WatchpointMapEntry>();
            entry->internal_watchpoint = std::make_unique<InternalWatchpoint>(domain, gfn);
            iter = watchpoints_.map_.try_emplace(gfn, std::move(entry)).first;
        }

        auto& entry = iter->second;
        std::lock_guard<decltype(WatchpointMapEntry::mtx)> lock2(entry->mtx);

        // Increment the requested intercepts
        if (watchpoint.read())
            if (++entry->read_count == 1)
                entry->internal_watchpoint->read(true);
        if (watchpoint.write())
            if (++entry->write_count == 1)
                entry->internal_watchpoint->write(true);
        if (watchpoint.execute())
            if (++entry->execute_count == 1)
                entry->internal_watchpoint->execute(true);

        entry->internal_watchpoint->update();
        entry->watchpoint_set.emplace(&watchpoint);
    }
}
void WatchpointManager::remove_ref(WatchpointImpl& watchpoint) {
    // Get a copy of the address starting at the beginning of the page
    auto address = watchpoint.address().clone();
    *address -= address->page_offset();

    // Round up to full pages
    const uint64_t length = round_to_page_size(watchpoint.length());
    const uint64_t end = address->value() + length;

    std::lock_guard<decltype(watchpoints_.mtx_)> watchpoint_lock(watchpoints_.mtx_);
    if (unlikely(interrupted_))
        return;

    for (; address->value() < end; *address += x86::PageDirectory::PAGE_SIZE) {
        GuestPhysicalAddress physical_address(*address);
        const uint64_t gfn = physical_address.page_number();

        LOG4CXX_DEBUG(logger, "Removing watchpoint for gfn 0x" << std::hex << gfn);

        auto iter = watchpoints_.map_.find(gfn);
        if (unlikely(iter == watchpoints_.map_.end()))
            throw std::runtime_error("Could not find gfn in WatchpointManager::remove_ref()");

        auto& entry = iter->second;
        std::lock_guard<decltype(WatchpointMapEntry::mtx)> lock2(entry->mtx);

        LOG4CXX_DEBUG(logger, "Pre R/W/X: " << entry->read_count << "," << entry->write_count << ","
                                            << entry->execute_count);

        // Decrement stuff
        if (watchpoint.read())
            if (--entry->read_count == 0)
                entry->internal_watchpoint->read(false);
        if (watchpoint.write())
            if (--entry->write_count == 0)
                entry->internal_watchpoint->write(false);
        if (watchpoint.execute())
            if (--entry->execute_count == 0)
                entry->internal_watchpoint->execute(false);

        LOG4CXX_DEBUG(logger, "Post R/W/X: " << entry->read_count << "," << entry->write_count
                                             << "," << entry->execute_count);

        entry->internal_watchpoint->update();

        if (entry->in_delivery) {
            // We're in the middle of the delivery loop, queue the watchpoint up to be removed
            LOG4CXX_DEBUG(logger, "Queued removal for watchpoint for gfn 0x" << std::hex << gfn);
            entry->pending_delete.insert(&watchpoint);
            continue;
        }

        // Not in delivery, we can remove it now.
        entry->watchpoint_set.erase(&watchpoint);
        if (entry->watchpoint_set.empty())
            watchpoints_.map_.erase(iter);
    }
}

bool WatchpointManager::deliver_watchpoint(Event& event) {
    auto& vcpu = event.vcpu();
    const uint64_t gfn = event.mem_access().physical_address().page_number();

    // Find the watchpoint for the event
    std::lock_guard<decltype(watchpoints_.mtx_)> watchpoint_lock(watchpoints_.mtx_);
    LOG4CXX_TRACE(logger, "VCPU " << vcpu.id() << ": Memory access event received for "
                                  << event.mem_access().physical_address() << " ["
                                  << (event.mem_access().read_violation() ? "R" : "")
                                  << (event.mem_access().write_violation() ? "W" : "")
                                  << (event.mem_access().execute_violation() ? "X" : "") << "]");

    auto iter = watchpoints_.map_.find(gfn);
    if (unlikely(iter == watchpoints_.map_.end())) {
        LOG4CXX_DEBUG(logger, "Memory access event for unknown address "
                                  << event.mem_access().physical_address());
        // Disable it
        static_cast<DomainImpl&>(event.domain()).intercept_mem_access(gfn, false, false, false);
        return false;
    }

    auto& entry = iter->second;
    std::lock_guard<decltype(entry->mtx)> lock(entry->mtx);
    entry->internal_watchpoint->disable();

    LOG4CXX_TRACE(logger, "VCPU " << vcpu.id() << ": Delivering memory access event for "
                                  << event.mem_access().physical_address());

    entry->in_delivery = true;
    for (auto* wp : entry->watchpoint_set) {
        try {
            if (entry->pending_delete.count(wp) == 0) {
                // Don't deliver to the same watchpoint more than one per step
                if (SteppingDelivered.count(wp) == 0) {
                    SteppingDelivered.insert(wp);

                    wp->deliver_event(event);
                }
            }
        } catch (TraceableException& ex) {
            LOG4CXX_WARN(logger, "Caught exception in deliver_watchpoint(): " << ex);
        }
    }
    entry->in_delivery = false;

    // Remove entries that are pending delete
    for (auto* wp : entry->pending_delete) {
        LOG4CXX_TRACE(logger, "Removing expired watchpoint");
        entry->watchpoint_set.erase(wp);
    }

    entry->pending_delete.clear();

    if (entry->watchpoint_set.empty()) {
        watchpoints_.map_.erase(iter);
        return false;
    }

    if (!entry->watchpoint_set.empty()) {
        SteppingWatchpoints.insert(entry.get());
        return true;
    }

    return false;
}

bool WatchpointManager::handle_mem_event(Event& event) {
    auto& vcpu = event.vcpu();

    if (unlikely(interrupted_)) {
        return false;
    }

    if (deliver_watchpoint(event)) {
        // Single step the guest
        stepping_active_ = true;
        LOG4CXX_TRACE(logger, "Mem event fixed, stepping VCPU " << vcpu.id());
        return true;
    } else {
        SteppingDelivered.clear();
        LOG4CXX_TRACE(logger, "Mem event cleared, not stepping VCPU " << vcpu.id());
        return false;
    }
}

void WatchpointManager::step(Event& event) {
    if (stepping_active_) {
        LOG4CXX_DEBUG(logger, "WP step on VCPU " << event.vcpu().id());

        // Restore the watchpoints that we disabled
        for (auto* watchpoint : SteppingWatchpoints) {
            watchpoint->internal_watchpoint->enable();
        }

        // Disable single stepping
        SteppingWatchpoints.clear();
        SteppingDelivered.clear();
        stepping_active_ = false;
    }
}

WatchpointManager::WatchpointManager() {}
WatchpointManager::~WatchpointManager() = default;

} // namespace introvirt