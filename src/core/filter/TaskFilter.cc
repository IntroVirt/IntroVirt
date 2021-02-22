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
#include <introvirt/core/event/Event.hh>
#include <introvirt/core/event/EventTaskInformation.hh>
#include <introvirt/core/filter/TaskFilter.hh>

#include <boost/algorithm/string.hpp>

namespace introvirt {

bool TaskFilter::matches(const Event& event) const {

    switch (event.type()) {
    case EventType::EVENT_SHUTDOWN:
    case EventType::EVENT_REBOOT:
        return true;
    default:
        break;
    }

    std::shared_lock<std::shared_mutex> read_lock(mtx_);
    auto& task_info = event.task();

    bool empty = true;

    if (!pid_filter_.empty()) {
        if (pid_filter_.count(task_info.pid()))
            return true;
        empty = false;
    }

    if (!tid_filter_.empty()) {
        if (tid_filter_.count(task_info.tid()))
            return true;
        empty = false;
    }

    if (!proc_name_filter_.empty()) {
        const std::string proc_name(boost::to_lower_copy(task_info.process_name()));
        for (const std::string& filter : proc_name_filter_) {
            if (boost::starts_with(proc_name, filter) || boost::starts_with(filter, proc_name))
                return true;
        }
        empty = false;
    }

    // The filter is empty, so just return the event
    if (empty)
        return true;

    // Our filter is not empty and we didn't have a match
    return false;
}

void TaskFilter::add_pid(uint64_t pid) {
    std::unique_lock<std::shared_mutex> write_lock(mtx_);
    pid_filter_.insert(pid);
}

bool TaskFilter::remove_pid(uint64_t pid) {
    std::unique_lock<std::shared_mutex> write_lock(mtx_);
    return pid_filter_.erase(pid);
}

void TaskFilter::add_tid(uint64_t tid) {
    std::unique_lock<std::shared_mutex> write_lock(mtx_);
    tid_filter_.insert(tid);
}

bool TaskFilter::remove_tid(uint64_t tid) {
    std::unique_lock<std::shared_mutex> write_lock(mtx_);
    return tid_filter_.erase(tid);
}

void TaskFilter::add_name(const std::string& name) {
    std::unique_lock<std::shared_mutex> write_lock(mtx_);
    proc_name_filter_.insert(boost::to_lower_copy(name));
}

bool TaskFilter::remove_name(const std::string& name) {
    std::unique_lock<std::shared_mutex> write_lock(mtx_);
    return proc_name_filter_.erase(boost::to_lower_copy(name));
}

void TaskFilter::clear() {
    std::unique_lock<std::shared_mutex> write_lock(mtx_);
    pid_filter_.clear();
    tid_filter_.clear();
    proc_name_filter_.clear();
}

} // namespace introvirt