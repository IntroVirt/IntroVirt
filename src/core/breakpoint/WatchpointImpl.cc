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
const guest_ptr<void>& WatchpointImpl::ptr() const { return ptr_; }
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
    guest_phys_ptr<void> addr = event.mem_access().physical_address();
    const uint64_t pfn = addr.address() >> PageDirectory::PAGE_SHIFT;

    // Check if we're in range
    if (pfn == first_pfn_ || pfn == last_pfn_) {
        if (pfn == first_pfn_)
            if (addr.address() < first_pfn_start_)
                return;
        if (pfn == last_pfn_)
            if (addr.address() > last_pfn_end_)
                return;
    }

    // If we're not the first or last page, then presumably we want this pfn.
    // If not, it's a bug in WatchpointManager.

    callback_(event);
}

WatchpointImpl::WatchpointImpl(const guest_ptr<void>& ptr, uint64_t length, bool read, bool write,
                               bool execute, std::function<void(Event&)> callback)
    : ptr_(ptr), length_(length), read_(read), write_(write), execute_(execute),
      callback_(callback) {

    if (unlikely(length == 0))
        throw BufferTooSmallException(1, 0);

    // Translate the physical address of the first frame
    first_pfn_start_ = ptr.domain().page_directory().translate(ptr.address(), ptr.page_directory());
    first_pfn_ = first_pfn_start_ >> PageDirectory::PAGE_SHIFT;

    last_pfn_end_ =
        ptr.domain().page_directory().translate(ptr.address() + (length - 1), ptr.page_directory());
    last_pfn_ = last_pfn_end_ >> PageDirectory::PAGE_SHIFT;
}

WatchpointImpl::~WatchpointImpl() {
    // Notify the watchpoint manager that we're done
    auto& domain = const_cast<DomainImpl&>(static_cast<const DomainImpl&>(ptr_.domain()));
    domain.watchpoint_manager().remove_ref(*this);
}

} // namespace introvirt