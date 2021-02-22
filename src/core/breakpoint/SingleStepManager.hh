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

#include <atomic>
#include <condition_variable>
#include <map>
#include <mutex>
#include <set>

namespace introvirt {

class SingleStepImpl;

struct SingleStepMapEntry {
    std::set<SingleStepImpl*> single_step_set;
    std::set<SingleStepImpl*> pending_delete;
    std::recursive_mutex mtx;
    bool in_delivery = false;
    uint64_t step_rip;
};

class SingleStepManager final {
  public:
    void handle_event(Event& event);

    void interrupt();

    void add_ref(SingleStepImpl& step);
    void remove_ref(SingleStepImpl& step);

    SingleStepManager();
    ~SingleStepManager();

  private:
    std::recursive_mutex mtx_;
    std::map<Vcpu*, std::unique_ptr<SingleStepMapEntry>> map_;
    std::atomic_bool interrupted_ = {false};

    std::mutex active_mtx_;
    int active_count_ = 0;
    std::condition_variable active_cv_;
};

} // namespace introvirt