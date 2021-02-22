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
#include "SingleStepManager.hh"
#include "SingleStepImpl.hh"
#include "core/domain/VcpuImpl.hh"

#include <introvirt/core/domain/Vcpu.hh>
#include <introvirt/util/compiler.hh>

#include <log4cxx/logger.h>

#include <stdexcept>

namespace introvirt {

static log4cxx::LoggerPtr
    logger(log4cxx::Logger::getLogger("introvirt.breakpoint.SingleStepManager"));

void SingleStepManager::add_ref(SingleStepImpl& step) {
    auto* vcpu = static_cast<VcpuImpl*>(&(step.vcpu()));

    std::unique_lock lock(mtx_);
    std::lock_guard active_lock(active_mtx_);

    auto iter = map_.find(vcpu);
    if (iter == map_.end()) {
        // Doesn't exist, create the entry and enable stepping
        auto& regs = vcpu->registers();

        LOG4CXX_TRACE(logger, "Enabling single-stepping on VCPU " << vcpu->id());
        iter = map_.emplace(vcpu, std::make_unique<SingleStepMapEntry>()).first;
        iter->second->step_rip = regs.rip();
        vcpu->single_step(true);
        ++active_count_;
    }

    auto& entry = iter->second;
    std::lock_guard lock2(entry->mtx);
    lock.unlock();

    entry->single_step_set.insert(&step);
}

void SingleStepManager::remove_ref(SingleStepImpl& step) {
    auto* vcpu = static_cast<VcpuImpl*>(&(step.vcpu()));

    std::unique_lock<decltype(mtx_)> lock(mtx_);
    auto iter = map_.find(vcpu);
    if (unlikely(iter == map_.end()))
        throw std::runtime_error("BUG: Missing entry in SingleStepManager::remove_ref()");

    auto& entry = iter->second;
    std::lock_guard lock2(entry->mtx);

    if (entry->in_delivery) {
        entry->pending_delete.insert(&step);
        return;
    }

    // Not in delivery, we're good to remove it from the real set
    entry->single_step_set.erase(&step);

    // TODO : Lock the VCPU so it can't complete the event it's handling until we are done
    // For now it has to complete one more single step to deactivate

    if (entry->single_step_set.empty() && vcpu->handling_event()) {
        std::lock_guard active_lock(active_mtx_);

        // Safe to remove the step now
        LOG4CXX_DEBUG(logger, "Disabling single-stepping on VCPU " << vcpu->id());
        vcpu->single_step(false);
        map_.erase(iter);

        --active_count_;
        if (active_count_ == 0)
            active_cv_.notify_all();
    }
}

void SingleStepManager::interrupt() {
    interrupted_ = true;

    std::unique_lock active_lock(active_mtx_);
    active_cv_.wait(active_lock, [this] { return active_count_ == 0; });
}

void SingleStepManager::handle_event(Event& event) {
    auto& vcpu = static_cast<VcpuImpl&>(event.vcpu());
    auto& regs = vcpu.registers();

    std::lock_guard lock(mtx_);
    std::lock_guard active_lock(active_mtx_);

    auto iter = map_.find(&vcpu);
    if (unlikely(iter == map_.end())) {
        // No one wants this event, disable single stepping
        // This shouldn't really happen
        if (vcpu.single_step()) {
            LOG4CXX_WARN(logger, "Disabling unwanted single-stepping on VCPU " << vcpu.id());
            vcpu.single_step(false);
        }
        return;
    }

    auto& entry = iter->second;
    std::lock_guard lock2(entry->mtx);

    // Deliver the event
    if (likely(entry->step_rip != regs.rip())) {
        LOG4CXX_TRACE(logger,
                      "Step from 0x" << std::hex << entry->step_rip << " to 0x" << regs.rip());
        entry->in_delivery = true;
        for (auto* single_step : entry->single_step_set) {
            if (entry->pending_delete.count(single_step) == 0) {
                single_step->deliver_event(event);
            }
        }
        entry->in_delivery = false;

        // Check for removed entries
        for (auto* single_step : entry->pending_delete) {
            entry->single_step_set.erase(single_step);
        }
        entry->pending_delete.clear();
    } else {
        LOG4CXX_WARN(logger, "Single step did not change RIP on VCPU " << vcpu.id());
    }

    if (!entry->single_step_set.empty()) {
        // Another step is pending, update the RIP
        entry->step_rip = regs.rip();
    } else {
        // No one wants this anymore, disable stepping
        LOG4CXX_TRACE(logger, "Disabling single-stepping on VCPU " << vcpu.id());
        vcpu.single_step(false);
        map_.erase(iter);
        --active_count_;
        if (active_count_ == 0)
            active_cv_.notify_all();
        return;
    }
}

SingleStepManager::SingleStepManager() = default;
SingleStepManager::~SingleStepManager() = default;

} // namespace introvirt