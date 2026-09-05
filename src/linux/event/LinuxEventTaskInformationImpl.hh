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

#include <introvirt/linux/event/LinuxEventTaskInformation.hh>

#include <cstdint>
#include <string>

namespace introvirt {

class Vcpu;

namespace linux_guest {

class LinuxGuest;

/**
 * @brief Concrete current-task info for a LinuxEvent.
 *
 * Resolution of the running task (per-CPU `current_task` via the kernel GS
 * base → task_struct.pid/tgid/comm using the profile offsets) is Phase 2 in
 * docs/introvirt-linux-port.md. Until then this returns zeros / "" — an
 * honest placeholder rather than an unvalidated guess at the per-CPU layout.
 * The interface + wiring are in place so the event path is complete and the
 * resolution can drop in without touching call sites.
 */
class LinuxEventTaskInformationImpl final : public LinuxEventTaskInformation {
  public:
    uint64_t pid() const override { return pid_; }
    uint64_t tid() const override { return tid_; }
    std::string process_name() const override { return comm_; }
    uint64_t task_struct_address() const override { return task_struct_address_; }

    LinuxEventTaskInformationImpl(LinuxGuest& guest, const Vcpu& vcpu);

  private:
    uint64_t task_struct_address_ = 0;
    uint64_t pid_ = 0;
    uint64_t tid_ = 0;
    std::string comm_;
};

} // namespace linux_guest
} // namespace introvirt
