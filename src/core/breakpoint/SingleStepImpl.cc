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
#include "SingleStepImpl.hh"
#include "core/domain/DomainImpl.hh"
#include "core/domain/VcpuImpl.hh"

namespace introvirt {

void SingleStepImpl::callback(std::function<void(Event&)> callback) { callback_ = callback; }
Vcpu& SingleStepImpl::vcpu() { return vcpu_; }
void SingleStepImpl::deliver_event(Event& event) { callback_(event); }

SingleStepImpl::SingleStepImpl(Vcpu& vcpu, std::function<void(Event&)> callback)
    : vcpu_(vcpu), callback_(callback) {}

SingleStepImpl::~SingleStepImpl() {
    // Notify the single-step manager that we're done
    auto& domain = const_cast<DomainImpl&>(static_cast<const DomainImpl&>(vcpu_.domain()));
    domain.single_step_manager().remove_ref(*this);
}

} // namespace introvirt