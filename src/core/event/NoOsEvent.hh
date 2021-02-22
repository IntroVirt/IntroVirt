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

#include "EventImpl.hh"

#include <introvirt/core/event/Event.hh>
#include <introvirt/core/exception/NotImplementedException.hh>

namespace introvirt {

class NoOsEvent final : public EventImplTpl<Event> {
  public:
    EventTaskInformation& task() override {
        throw NotImplementedException(
            "Guest OS either not detected or implemented, cannot provide task information");
    }

    const EventTaskInformation& task() const override {
        throw NotImplementedException(
            "Guest OS either not detected or implemented, cannot provide task information");
    }

    SystemCallEvent& syscall() override {
        throw NotImplementedException(
            "Guest OS either not detected or implemented, cannot provide system call information");
    }
    const SystemCallEvent& syscall() const override {
        throw NotImplementedException(
            "Guest OS either not detected or implemented, cannot provide system call information");
    }

    uint64_t thread_id() const override {
        throw NotImplementedException(
            "Guest OS either not detected or implemented, cannot provide thread_id");
    }

    NoOsEvent(std::unique_ptr<HypervisorEvent>&& hypervisor_event)
        : EventImplTpl<Event>(std::move(hypervisor_event)) {}

  private:
};

} // namespace introvirt