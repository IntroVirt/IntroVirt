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
#include "BreakpointImpl.hh"
#include "BreakpointManager.hh"
#include "core/domain/DomainImpl.hh"

#include <introvirt/util/compiler.hh>

namespace introvirt {

std::shared_ptr<void> BreakpointImpl::data() { return data_; }
std::shared_ptr<const void> BreakpointImpl::data() const { return data_; }

void BreakpointImpl::data(const std::shared_ptr<void>& value) { data_ = value; }
void BreakpointImpl::data(std::shared_ptr<void>&& value) { data_ = std::move(value); }

void BreakpointImpl::callback(std::function<void(Event&)> callback) {
    std::lock_guard lock(cbdata_->mtx_);
    cbdata_->callback_ = callback;
}

const GuestPhysicalAddress& BreakpointImpl::address() const { return address_; }

BreakpointImpl::BreakpointImpl(const GuestAddress& address, std::function<void(Event&)> callback)
    : address_(address.domain(), address.physical_address()),
      cbdata_(std::make_shared<BreakpointImplCallback>(std::move(callback))) {}

BreakpointImpl::~BreakpointImpl() {
    // Notify the breakpoint manager that we're done
    cbdata_->destroyed_ = true;

    auto& domain = const_cast<DomainImpl&>(static_cast<const DomainImpl&>(address_.domain()));
    domain.breakpoint_manager().remove_ref(*this);
}

} // namespace introvirt