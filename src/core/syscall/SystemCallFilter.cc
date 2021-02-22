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
#include <introvirt/core/domain/Vcpu.hh>
#include <introvirt/core/event/Event.hh>
#include <introvirt/core/event/SystemCallEvent.hh>
#include <introvirt/core/syscall/SystemCallFilter.hh>
#include <introvirt/util/compiler.hh>

#include <algorithm>
#include <mutex>
#include <vector>

#include <log4cxx/logger.h>

static log4cxx::LoggerPtr logger(log4cxx::Logger::getLogger("introvirt.syscall.SystemCallFilter"));

namespace introvirt {

static constexpr size_t MaxCall = 16384;

class SystemCallFilter::IMPL {
  public:
    void clear() {
        std::lock_guard lock(mtx_);

        std::fill(filter_32_.begin(), filter_32_.end(), 0);
        std::fill(filter_64_.begin(), filter_64_.end(), 0);
    }

    bool matches(unsigned int index, std::vector<bool>& filter) const {
        index &= mask_;

        // The incoming system call number is larger than we can fit in our map
        if (unlikely(index >= MaxCall)) {
            LOG4CXX_WARN(logger, "Rejecting incoming system call index "
                                     << index << ": Index too large for bitmap");
            return false;
        }

        std::lock_guard lock(mtx_);
        return filter.at(index);
    }

    void set(unsigned int index, std::vector<bool>& filter, bool enabled) {
        if (unlikely(index == 0xFFFFFFFF)) {
            LOG4CXX_DEBUG(
                logger,
                "Skipping system call -1, likely the guest does not support the intended call");
            return;
        }

        index &= mask_;

        // The incoming system call number is larger than we can fit in our map
        if (unlikely(index >= MaxCall)) {
            LOG4CXX_WARN(logger, "Rejecting set for system call index "
                                     << index << ": Index too large for bitmap");
            return;
        }

        std::lock_guard lock(mtx_);
        filter[index] = enabled;
    }

    IMPL() {
        filter_32_.resize(MaxCall, false);
        filter_64_.resize(MaxCall, false);
    }

  public:
    mutable std::mutex mtx_;

    std::vector<bool> filter_32_;
    std::vector<bool> filter_64_;

    bool enabled_ = false;
    uint32_t mask_;
};

SystemCallFilter::SystemCallFilter() : pImpl_(std::make_unique<IMPL>()) {}

bool SystemCallFilter::matches(const Event& event) const {
    if (event.vcpu().long_mode()) {
        return pImpl_->matches(event.syscall().raw_index(), pImpl_->filter_64_);
    } else {
        return pImpl_->matches(event.syscall().raw_index(), pImpl_->filter_32_);
    }
}

bool SystemCallFilter::matches(const Vcpu& vcpu) const {
    if (vcpu.long_mode()) {
        return pImpl_->matches(vcpu.registers().rax(), pImpl_->filter_64_);
    } else {
        return pImpl_->matches(vcpu.registers().rax(), pImpl_->filter_32_);
    }
}

void SystemCallFilter::set_32(uint32_t index, bool enabled) {
    pImpl_->set(index, pImpl_->filter_32_, enabled);
}

void SystemCallFilter::set_64(uint32_t index, bool enabled) {
    pImpl_->set(index, pImpl_->filter_64_, enabled);
}

void SystemCallFilter::clear() { pImpl_->clear(); }

void SystemCallFilter::mask(uint64_t mask) { pImpl_->mask_ = mask; }
uint64_t SystemCallFilter::mask() const { return pImpl_->mask_; }

void SystemCallFilter::enabled(bool enabled) {
    std::lock_guard lock(pImpl_->mtx_);

    pImpl_->enabled_ = enabled;
}

bool SystemCallFilter::enabled() const {
    std::lock_guard lock(pImpl_->mtx_);
    return pImpl_->enabled_;
}

SystemCallFilter::~SystemCallFilter() = default;

} // namespace introvirt
