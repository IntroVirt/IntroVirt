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

#include "core/event/HypervisorEvent.hh"

#include <introvirt/core/event/ControlRegisterEvent.hh>

namespace introvirt {

class ControlRegisterEventImpl : public ControlRegisterEvent {
  public:
    int index() const final { return hypervisor_event_.control_register(); }
    uint64_t value() const final { return hypervisor_event_.control_register_value(); }

    ControlRegisterEventImpl(HypervisorEvent& hypervisor_event)
        : hypervisor_event_(hypervisor_event) {}

  private:
    HypervisorEvent& hypervisor_event_;
};

} // namespace introvirt