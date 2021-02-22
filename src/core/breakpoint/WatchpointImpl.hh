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

#include <introvirt/core/breakpoint/Watchpoint.hh>
#include <introvirt/core/event/Event.hh>
#include <introvirt/core/memory/GuestAddress.hh>

#include <cstdint>
#include <functional>
#include <memory>

namespace introvirt {

class WatchpointImpl final : public Watchpoint {
  public:
    void callback(std::function<void(Event&)> callback) override;

    const GuestAddress& address() const;
    uint64_t length() const;
    bool read() const;
    bool write() const;
    bool execute() const;

    void deliver_event(Event& event);

    WatchpointImpl(const GuestAddress& address, uint64_t length, bool read, bool write,
                   bool execute, std::function<void(Event&)> callback);
    ~WatchpointImpl();

  private:
    std::unique_ptr<GuestAddress> address_;
    const uint64_t length_;
    const bool read_;
    const bool write_;
    const bool execute_;
    std::function<void(Event&)> callback_;

    uint64_t first_pfn_;
    uint64_t first_pfn_start_;
    uint64_t last_pfn_;
    uint64_t last_pfn_end_;
};

} // namespace introvirt