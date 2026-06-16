/*
 * Copyright 2026 SecTepe.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *         http://www.apache.org/licenses/LICENSE-2.0
 */
#include "LinuxEventImpl.hh"

#include <introvirt/core/event/EventType.hh>
#include <introvirt/core/exception/InvalidMethodException.hh>

namespace introvirt {
namespace linux_guest {

LinuxEventImpl::LinuxEventImpl(LinuxGuest& guest,
                              std::unique_ptr<HypervisorEvent>&& hypervisor_event)
    : EventImplTpl<LinuxEvent>(std::move(hypervisor_event)), guest_(guest),
      task_info_(guest, vcpu()) {
    // Build the syscall view for fast-syscall events (mirrors WindowsEventImpl).
    switch (type()) {
    case EventType::EVENT_FAST_SYSCALL:
    case EventType::EVENT_FAST_SYSCALL_RET:
        syscall_.emplace(*hypervisor_event_);
        break;
    default:
        break;
    }
}

SystemCallEvent& LinuxEventImpl::syscall() {
    if (!syscall_)
        throw InvalidMethodException();
    return *syscall_;
}

const SystemCallEvent& LinuxEventImpl::syscall() const {
    if (!syscall_)
        throw InvalidMethodException();
    return *syscall_;
}

} // namespace linux_guest
} // namespace introvirt
