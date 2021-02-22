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

#include <introvirt/core/event/SystemCallEvent.hh>

#include <memory>

namespace introvirt {

class SystemCallEventImpl {
  public:
    virtual std::unique_ptr<SystemCall> release_handler() = 0;
    virtual void handler(std::unique_ptr<SystemCall>&& handler) = 0;

    virtual void raw_index(uint64_t value) = 0;
};

template <typename _BaseClass>
class SystemCallEventImplTpl : public _BaseClass, public SystemCallEventImpl {
  public:
    FastCallType instruction() const override { return hypervisor_event_.system_call_type(); }

    void hook_return(bool enabled) override { hook_return_ = enabled; }
    bool hook_return() const override { return hook_return_; }

    uint64_t return_address() const override { return hypervisor_event_.syscall_return_address(); }

    SystemCallEventImpl& impl() final { return *this; }

    SystemCallEventImplTpl(HypervisorEvent& hypervisor_event)
        : hypervisor_event_(hypervisor_event) {}

  protected:
    HypervisorEvent& hypervisor_event_;

  private:
    bool hook_return_ = false;
};

} // namespace introvirt