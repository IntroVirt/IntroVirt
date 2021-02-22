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

#include <introvirt/core/event/Event.hh>
#include <introvirt/core/memory/guest_ptr.hh>

#include <atomic>
#include <cstdint>
#include <memory>
#include <mutex>
#include <set>
#include <unordered_map>

namespace introvirt {

class DomainImpl;
class WatchpointImpl;

class InternalWatchpoint final {
  public:
    /**
     * @brief Enable the watchpoint
     */
    void enable();

    /**
     * @brief Disable the watchpoint
     */
    void disable();

    bool read() const;
    void read(bool val);

    bool write() const;
    void write(bool val);

    bool execute() const;
    void execute(bool val);

    void update();

    InternalWatchpoint(DomainImpl& domain, uint64_t gfn);
    ~InternalWatchpoint();

  private:
    DomainImpl& domain_;
    const uint64_t gfn_;
    bool read_ = false;
    bool write_ = false;
    bool execute_ = false;
    bool enabled_ = true;

    bool current_read_ = false;
    bool current_write_ = false;
    bool current_execute_ = false;
};

struct WatchpointMapEntry {
    std::unique_ptr<InternalWatchpoint> internal_watchpoint;
    std::set<WatchpointImpl*> watchpoint_set;
    std::set<WatchpointImpl*> pending_delete;

    int read_count = 0;
    int write_count = 0;
    int execute_count = 0;

    bool in_delivery = false;

    std::recursive_mutex mtx;
};

class WatchpointManager final {
  public:
    bool handle_mem_event(Event& event);
    void step(Event& event);

    void interrupt();

    void add_ref(WatchpointImpl& breakpoint);
    void remove_ref(WatchpointImpl& breakpoint);

    WatchpointManager();
    ~WatchpointManager();

  private:
    /**
     * @return true if there are still active watchpoints for this gfn
     * @return false if there are no active watchpoints for this gfn
     */
    bool deliver_watchpoint(Event& event);

    bool stepping_active_ = false;

    struct {
        std::recursive_mutex mtx_;
        std::unordered_map<uint64_t, std::unique_ptr<WatchpointMapEntry>> map_;
    } watchpoints_;

    std::atomic_bool interrupted_ = {false};
};

} // namespace introvirt