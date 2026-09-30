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

#include <cstring>
#include <mutex>
#include <new>

#include <sys/mman.h>

#include <log4cxx/logger.h>

static log4cxx::LoggerPtr logger(log4cxx::Logger::getLogger("introvirt.syscall.SystemCallFilter"));

namespace introvirt {

/* Must match struct kvm_syscall_filter in the kvm-introvirt UAPI. */
static constexpr size_t FilterPageSize = 4096;
static constexpr size_t BitmapBytes = 2040;
static constexpr size_t MaxCall = BitmapBytes * 8; /* 16320 */

struct FilterPage {
    uint32_t enabled;
    uint32_t mask;
    uint32_t deliver_returns;
    uint32_t pad;
    uint8_t bits32[BitmapBytes];
    uint8_t bits64[BitmapBytes];
};
static_assert(sizeof(FilterPage) == FilterPageSize, "SystemCallFilter page must be 4KiB");

class SystemCallFilter::IMPL {
  public:
    void clear() {
        std::lock_guard lock(mtx_);
        std::memset(page_->bits32, 0, sizeof(page_->bits32));
        std::memset(page_->bits64, 0, sizeof(page_->bits64));
    }

    bool matches(unsigned int index, const uint8_t* bits) const {
        index &= page_->mask;

        if (unlikely(index >= MaxCall)) {
            LOG4CXX_WARN(logger, "Rejecting incoming system call index "
                                     << index << ": Index too large for bitmap");
            return false;
        }

        std::lock_guard lock(mtx_);
        return (bits[index >> 3] & (1u << (index & 7))) != 0;
    }

    void set(unsigned int index, uint8_t* bits, bool enabled) {
        if (unlikely(index == 0xFFFFFFFF)) {
            LOG4CXX_DEBUG(
                logger,
                "Skipping system call -1, likely the guest does not support the intended call");
            return;
        }

        index &= page_->mask;

        if (unlikely(index >= MaxCall)) {
            LOG4CXX_WARN(logger, "Rejecting set for system call index "
                                     << index << ": Index too large for bitmap");
            return;
        }

        std::lock_guard lock(mtx_);
        const uint8_t bit = static_cast<uint8_t>(1u << (index & 7));
        if (enabled)
            bits[index >> 3] |= bit;
        else
            bits[index >> 3] &= static_cast<uint8_t>(~bit);
    }

    IMPL() {
        void* mapping = mmap(nullptr, FilterPageSize, PROT_READ | PROT_WRITE,
                             MAP_SHARED | MAP_ANONYMOUS, -1, 0);
        if (mapping == MAP_FAILED)
            throw std::bad_alloc();

        page_ = static_cast<FilterPage*>(mapping);
        std::memset(page_, 0, FilterPageSize);
        page_->mask = 0xFFFFFFFFu;
        page_->deliver_returns = 1;
    }

    ~IMPL() {
        if (page_)
            munmap(page_, FilterPageSize);
    }

  public:
    mutable std::mutex mtx_;
    FilterPage* page_ = nullptr;
};

SystemCallFilter::SystemCallFilter() : pImpl_(std::make_unique<IMPL>()) {}

bool SystemCallFilter::matches(const Event& event) const {
    if (event.vcpu().long_mode()) {
        return pImpl_->matches(event.syscall().raw_index(), pImpl_->page_->bits64);
    } else {
        return pImpl_->matches(event.syscall().raw_index(), pImpl_->page_->bits32);
    }
}

bool SystemCallFilter::matches(const Vcpu& vcpu) const {
    if (vcpu.long_mode()) {
        return pImpl_->matches(vcpu.registers().rax(), pImpl_->page_->bits64);
    } else {
        return pImpl_->matches(vcpu.registers().rax(), pImpl_->page_->bits32);
    }
}

void SystemCallFilter::set_32(uint32_t index, bool enabled) {
    pImpl_->set(index, pImpl_->page_->bits32, enabled);
}

void SystemCallFilter::set_64(uint32_t index, bool enabled) {
    pImpl_->set(index, pImpl_->page_->bits64, enabled);
}

void SystemCallFilter::clear() { pImpl_->clear(); }

void SystemCallFilter::mask(uint64_t mask) { pImpl_->page_->mask = static_cast<uint32_t>(mask); }
uint64_t SystemCallFilter::mask() const { return pImpl_->page_->mask; }

void SystemCallFilter::enabled(bool enabled) { pImpl_->page_->enabled = enabled ? 1 : 0; }

bool SystemCallFilter::enabled() const { return pImpl_->page_->enabled != 0; }

void SystemCallFilter::deliver_returns(bool enabled) {
    pImpl_->page_->deliver_returns = enabled ? 1 : 0;
}

bool SystemCallFilter::deliver_returns() const { return pImpl_->page_->deliver_returns != 0; }

void* SystemCallFilter::page() const { return pImpl_->page_; }

SystemCallFilter::~SystemCallFilter() = default;

} // namespace introvirt
