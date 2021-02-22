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

#include <set>
#include <shared_mutex>
#include <unordered_set>

namespace introvirt {

/**
 * @brief Filter to remove events based on task
 *
 * This class allows you to filter for events related to a
 * process, thread, or process name. Adding an entry to the list
 * means that events will be delivered for tasks matching the entry.
 *
 */
class TaskFilter final {
  public:
    /**
     * @brief Add a process ID
     *
     * @param pid The PID to filter for
     */
    void add_pid(uint64_t pid);

    /**
     * @brief Remove a process ID
     *
     * @param pid The PID to remove
     * @return true if the PID was removed
     * @return false if the PID was not found
     */
    bool remove_pid(uint64_t pid);

    /**
     * @brief Add a thread ID
     *
     * @param tid The TID to filter for
     */
    void add_tid(uint64_t tid);

    /**
     * @brief Remove a thread ID
     *
     * @param tid The TID to remove
     * @return true if the TID was removed
     * @return false if the TID was not found
     */
    bool remove_tid(uint64_t tid);

    /**
     * @brief Add a process name to the filter
     *
     * The name comparison is case-insensitive.
     * It's also only treated as a prefix. For
     * example, "exp" will match "explorer.exe".
     *
     * @param name The name to add
     */
    void add_name(const std::string& name);

    /**
     * @brief Remove a process name from the filter
     *
     * @param name The name to remove
     * @return true if the name was removed
     * @return false if the name was not found
     */
    bool remove_name(const std::string& name);

    /**
     * @brief Clear all filters
     *
     * This will let all calls through
     */
    void clear();

    /**
     * @brief Check if the event matches our task filter
     *
     * @param event
     * @return true
     * @return false
     */
    bool matches(const Event& event) const;

    TaskFilter() = default;
    ~TaskFilter() = default;

  private:
    mutable std::shared_mutex mtx_;
    std::unordered_set<uint64_t> tid_filter_;
    std::unordered_set<uint64_t> pid_filter_;
    std::set<std::string> proc_name_filter_;
};

} // namespace introvirt