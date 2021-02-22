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

#include "core/domain/DomainImpl.hh"

#include <introvirt/core/breakpoint/Breakpoint.hh>
#include <introvirt/core/memory/GuestPhysicalAddress.hh>

#include <cstdint>
#include <memory>
#include <mutex>

namespace introvirt {

class InternalBreakpoint;

/**
 * This is a separate class so that BreakpointImpl can go off scope while leaving a valid
 * BreakpointImplCallback. The BreakpointImplCallback will have it's callback set to nullptr.
 *
 */
class BreakpointImplCallback {
  public:
    void deliver_event(Event& event) {
        if (likely(!destroyed_))
            callback_(event);
    }

    BreakpointImplCallback(std::function<void(Event&)>&& callback)
        : callback_(std::move(callback)) {}

    std::function<void(Event&)> callback_;
    std::recursive_mutex mtx_;
    std::atomic_bool destroyed_ = false;
};

class BreakpointImpl final : public Breakpoint {
  public:
    std::shared_ptr<void> data() override;
    std::shared_ptr<const void> data() const override;

    void data(const std::shared_ptr<void>& value) override;
    void data(std::shared_ptr<void>&& value) override;

    void callback(std::function<void(Event&)> callback) override;

    const GuestPhysicalAddress& address() const;

    std::shared_ptr<BreakpointImplCallback> callback() { return cbdata_; }

    void internal_breakpoint(const std::shared_ptr<InternalBreakpoint>& internal_breakpoint) {
        internal_breakpoint_ = internal_breakpoint;
    }

    std::shared_ptr<InternalBreakpoint> internal_breakpoint() { return internal_breakpoint_; }

    BreakpointImpl(const GuestAddress& address, std::function<void(Event&)> callback);

    ~BreakpointImpl() override;

  private:
    const GuestPhysicalAddress address_;
    std::shared_ptr<BreakpointImplCallback> cbdata_;
    std::shared_ptr<void> data_;
    std::shared_ptr<InternalBreakpoint> internal_breakpoint_;
};

} // namespace introvirt
