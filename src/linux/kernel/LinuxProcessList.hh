/*
 * Copyright 2026 SecTepe.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *         http://www.apache.org/licenses/LICENSE-2.0
 */
#pragma once

#include "linux/kernel/LinuxTask.hh"

#include <cstdint>
#include <vector>

namespace introvirt {

class Domain;

namespace linux_guest {

class LinuxKernel;

/**
 * @brief Enumerates the guest's tasks by walking `init_task.tasks`.
 *
 * The kernel keeps every task on a doubly-linked `list_head` rooted at
 * `init_task.tasks`. Starting at `init_task` and following `.next` until we
 * return to the root yields one node per task; each node sits at
 * `task_struct + offsetof(task_struct, tasks)`, so the task_struct address is
 * `node - tasks_offset`. This is the standard Volatility-style walk and the
 * foundation for `ivprocinfo` on Linux.
 *
 * Reads are defensive: an unmapped node or a cycle longer than a sane bound
 * ends the walk rather than throwing/looping forever.
 */
class LinuxProcessList {
  public:
    LinuxProcessList(const LinuxKernel& kernel, const Domain& domain, uint64_t page_directory);

    /**
     * @brief All tasks reachable from init_task.tasks (excluding init_task).
     */
    std::vector<LinuxTask> tasks() const;

  private:
    const LinuxKernel& kernel_;
    const Domain& domain_;
    uint64_t page_directory_;
};

} // namespace linux_guest
} // namespace introvirt
