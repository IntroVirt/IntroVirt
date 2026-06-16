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
namespace linux_guest {

/**
 * @brief A process/task enumerated from a Linux guest.
 *
 * The public, OS-generic-shaped view a tool (e.g. ivprocinfo) consumes,
 * built from a `task_struct` read via the profile offsets. Values are
 * snapshotted at enumeration time.
 */
class LinuxProcess {
  public:
    int32_t pid() const { return pid_; }   ///< userspace PID (task_struct.tgid)
    int32_t tid() const { return tid_; }   ///< thread id     (task_struct.pid)
    const std::string& name() const { return name_; } ///< task_struct.comm
    uint64_t task_struct_address() const { return task_struct_address_; }

    LinuxProcess(int32_t pid, int32_t tid, std::string name, uint64_t task_struct_address)
        : pid_(pid), tid_(tid), name_(std::move(name)),
          task_struct_address_(task_struct_address) {}

  private:
    int32_t pid_;
    int32_t tid_;
    std::string name_;
    uint64_t task_struct_address_;
};

} // namespace linux_guest
} // namespace introvirt
