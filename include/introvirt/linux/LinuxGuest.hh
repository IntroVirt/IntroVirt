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

#include <introvirt/core/domain/Guest.hh>
#include <introvirt/fwd.hh>

namespace introvirt {
namespace linux_guest {

class LinuxKernel;

/**
 * @brief A representation of a Linux Guest OS.
 *
 * Mirrors ``windows::WindowsGuest``: the OS-specific face of the generic
 * ``Guest`` interface. The concrete ``LinuxGuestImpl`` (added in a later
 * increment) also implements ``GuestImpl`` and is constructed from
 * ``DomainImpl::detect_guest()`` once a Linux kernel is detected.
 *
 * Unlike Windows there is no syscall *converter* here yet — the Linux
 * syscall table + handler classes (Phase 3 in docs/introvirt-linux-port.md)
 * are generated separately and wired in when ``ivsyscallmon`` support lands.
 */
class LinuxGuest : public Guest {
  public:
    /**
     * @brief Get the Linux kernel parser.
     */
    virtual LinuxKernel& kernel() = 0;

    /**
     * @copydoc LinuxGuest::kernel()
     */
    virtual const LinuxKernel& kernel() const = 0;

    /**
     * @brief Get the Domain instance the guest is running on.
     */
    virtual Domain& domain() = 0;

    /**
     * @copydoc LinuxGuest::domain()
     */
    virtual const Domain& domain() const = 0;

    virtual ~LinuxGuest() = default;
};

} // namespace linux_guest
} // namespace introvirt
