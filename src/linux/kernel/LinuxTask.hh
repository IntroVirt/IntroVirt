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

#include <cstdint>
#include <string>

namespace introvirt {

class Domain;

namespace linux_guest {

class LinuxKernel;

/**
 * @brief Reads one `task_struct` from guest memory via the profile offsets.
 *
 * The reusable primitive the Linux process model is built on: given a
 * task_struct's kernel virtual address it exposes pid/tgid/comm/mm. The
 * process list (walking `init_task.tasks`) and the per-CPU current-task
 * resolution both build on this (Phase 2 in docs/introvirt-linux-port.md).
 *
 * Fields are read lazily on access (no caching) so a LinuxTask is cheap to
 * construct while iterating a task list.
 */
class LinuxTask {
  public:
    /**
     * @param kernel          resolves the task_struct member offsets
     * @param domain          guest to read from
     * @param page_directory  CR3 / pgd used to translate the reads
     * @param task_address    kernel virtual address of the task_struct
     */
    LinuxTask(const LinuxKernel& kernel, const Domain& domain, uint64_t page_directory,
              uint64_t task_address);

    uint64_t address() const { return task_address_; }

    int32_t pid() const;   ///< task_struct.pid  (thread id, Linux sense)
    int32_t tgid() const;  ///< task_struct.tgid (process id)
    std::string comm() const; ///< task_struct.comm (<=16 bytes, NUL-padded)
    uint64_t mm() const;   ///< task_struct.mm pointer (0 for kernel threads)

  private:
    int64_t offset(const char* member) const;

    const LinuxKernel& kernel_;
    const Domain& domain_;
    uint64_t page_directory_;
    uint64_t task_address_;
};

} // namespace linux_guest
} // namespace introvirt
