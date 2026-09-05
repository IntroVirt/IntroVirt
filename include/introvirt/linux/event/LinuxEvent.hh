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

#include <introvirt/core/event/Event.hh>
#include <introvirt/linux/event/LinuxEventTaskInformation.hh>
#include <introvirt/linux/fwd.hh>

namespace introvirt {
namespace linux_guest {

/**
 * @brief A Linux-specific hypervisor event (mirrors windows::WindowsEvent).
 *
 * Narrows Event::task() to LinuxEventTaskInformation (covariant return) and
 * exposes the owning LinuxGuest. There is no covariant syscall() yet — the
 * Linux syscall view (LinuxSystemCallEvent + the generated table) is Phase 3.
 */
class LinuxEvent : public Event {
  public:
    virtual LinuxEventTaskInformation& task() = 0;
    virtual const LinuxEventTaskInformation& task() const = 0;

    virtual LinuxGuest& guest() = 0;
    virtual const LinuxGuest& guest() const = 0;
};

} // namespace linux_guest
} // namespace introvirt
