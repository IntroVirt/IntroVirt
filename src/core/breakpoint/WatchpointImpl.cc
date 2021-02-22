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
#include "WatchpointImpl.hh"

#include "core/domain/DomainImpl.hh"

#include <introvirt/core/exception/BufferTooSmallException.hh>

namespace introvirt {

void WatchpointImpl::callback(std::function<void(Event&)> callback) { callback_ = callback; }
const GuestAddress& WatchpointImpl::address() const { return *address_; }
uint64_t WatchpointImpl::length() const { return length_; }
bool WatchpointImpl::read() const { return read_; }
bool WatchpointImpl::write() const { return write_; }
bool WatchpointImpl::execute() const { return execute_; }

void WatchpointImpl::deliver_event(Event& event) {
    auto& mem_access = event.mem_access();
    const bool read_violation = mem_access.read_violation();
    const bool write_violation = mem_access.write_violation();
    const bool execute_violation = mem_access.execute_violation();

    // Check if we care about this access
    if (!((read_violation && read()) || (write_violation && write()) ||
          (execute_violation && execute())))
        return;

    // Check if the target address is in our range
    auto addr = event.mem_access().physical_address();
    const uint64_t pfn = addr.page_number();

    // Check if we're in range
    if (pfn == first_pfn_ || pfn == last_pfn_) {
        if (pfn == first_pfn_)
            if (addr.value() < first_pfn_start_)
                return;
        if (pfn == last_pfn_)
            if (addr.value() > last_pfn_end_)
                return;
    }

    // If we're not the first or last page, then presumably we want this pfn.
    // If not, it's a bug in WatchpointManager.

    callback_(event);
}

WatchpointImpl::WatchpointImpl(const GuestAddress& address, uint64_t length, bool read, bool write,
                               bool execute, std::function<void(Event&)> callback)
    : address_(address.clone()), length_(length), read_(read), write_(write), execute_(execute),
      callback_(callback) {

    if (unlikely(length == 0))
        throw BufferTooSmallException(1, 0);

    // Translate the physical address
    address_->physical_address();

    auto addr_copy = address_->clone();

    // Do math
    GuestPhysicalAddress first_gpa(*addr_copy);
    first_pfn_ = first_gpa.page_number();
    first_pfn_start_ = first_gpa.value();

    *addr_copy += (length - 1);
    GuestPhysicalAddress last_gpa(*addr_copy);

    last_pfn_ = last_gpa.page_number();
    last_pfn_end_ = last_gpa.value();
}

WatchpointImpl::~WatchpointImpl() {
    // Notify the watchpoint manager that we're done
    auto& domain = const_cast<DomainImpl&>(static_cast<const DomainImpl&>(address_->domain()));
    domain.watchpoint_manager().remove_ref(*this);
}

} // namespace introvirt