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

#include "WindowsEventImpl.hh"
#include "core/event/SystemCallEventImpl.hh"
#include "windows/kernel/SystemCallCreator.hh"

#include <introvirt/windows/WindowsGuest.hh>
#include <introvirt/windows/event/WindowsEvent.hh>
#include <introvirt/windows/event/WindowsSystemCallEvent.hh>

namespace introvirt {
namespace windows {

class WindowsSystemCallEventImpl final : public SystemCallEventImplTpl<WindowsSystemCallEvent> {
  public:
    WindowsSystemCall* handler() override {
        const auto* const_this = this;
        return const_cast<WindowsSystemCall*>(const_this->handler());
    }

    const WindowsSystemCall* handler() const override {
        if (!system_call_.get()) {
            // Create the handler
            system_call_ = SystemCallCreator::make_unique(event_);
        }
        return system_call_.get();
    }

    std::unique_ptr<SystemCall> release_handler() override { return std::move(system_call_); }
    void handler(std::unique_ptr<SystemCall>&& handler) override {
        system_call_.reset(static_cast<WindowsSystemCall*>(handler.release()));
    }

    uint64_t raw_index() const override { return raw_index_; }
    void raw_index(uint64_t value) override {
        raw_index_ = value;
        index_ = event_.guest().syscalls().normalize(raw_index_);
    }

    SystemCallIndex index() const override { return index_; }
    std::string name() const override { return to_string(index_); }

    WindowsSystemCallEventImpl(WindowsEvent& event, HypervisorEvent& hypervisor_event)
        : SystemCallEventImplTpl<WindowsSystemCallEvent>(hypervisor_event), event_(event) {

        if (hypervisor_event.type() == EventType::EVENT_FAST_SYSCALL) {
            raw_index(hypervisor_event.vcpu().registers().rax());
        }
    }

  private:
    WindowsEvent& event_;
    mutable std::unique_ptr<WindowsSystemCall> system_call_;
    SystemCallIndex index_;
    uint64_t raw_index_;
};

} // namespace windows
} // namespace introvirt