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

#include <introvirt/core/event/EventTaskInformation.hh>

#include <cstdint>

namespace introvirt {
namespace linux_guest {

/**
 * @brief Linux task information for an event (the Linux analogue of
 * windows::WindowsEventTaskInformation).
 *
 * Adds the current task_struct address on top of the generic pid/tid/comm.
 */
class LinuxEventTaskInformation : public EventTaskInformation {
  public:
    /**
     * @brief Kernel virtual address of the current task_struct, or 0 if it
     *        could not be resolved.
     */
    virtual uint64_t task_struct_address() const = 0;

    // EventTaskInformation declares no (virtual) destructor, so this can't be
    // `override`; declare our own virtual dtor.
    virtual ~LinuxEventTaskInformation() = default;
};

} // namespace linux_guest
} // namespace introvirt
