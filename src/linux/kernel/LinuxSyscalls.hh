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
 * @brief x86_64 Linux syscall number → name lookup.
 *
 * A curated table of the common, version-stable x86_64 syscalls (the ones
 * that matter for malware behaviour — file, network, process, exec). Unknown
 * numbers fall back to `"sys_<nr>"`, matching the hybrid linux-syscalls-direct
 * tracer's convention, so the runner's classifier (which strips the `sys_`
 * prefix) handles either form.
 *
 * This is the naming foundation for `ivsyscallmon` on Linux. Argument
 * decoding + per-syscall handler classes (the full win_syscall_generator
 * analogue) come later; for completeness the table can be regenerated from a
 * kernel's `arch/x86/entry/syscalls/syscall_64.tbl`.
 */
class LinuxSyscalls {
  public:
    /**
     * @brief Name for an x86_64 syscall number (e.g. 257 -> "openat"), or
     *        "sys_<nr>" if not in the curated table.
     */
    static std::string name(uint32_t number);
};

} // namespace linux_guest
} // namespace introvirt
