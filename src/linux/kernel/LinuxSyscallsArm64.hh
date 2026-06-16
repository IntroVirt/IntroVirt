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
 * @brief AArch64 (arm64) Linux syscall number → name lookup.
 *
 * arm64 does NOT share x86_64's syscall numbers: it uses the architecture's
 * `asm-generic` table (`include/uapi/asm-generic/unistd.h`), so `read=63`,
 * `openat=56` (there is no bare `open`), `execve=221`, `clone=220`,
 * `socket=198`, `mmap=222`. This curated table covers the common,
 * version-stable calls that matter for malware behaviour (file, network,
 * process, exec); unknown numbers fall back to `"sys_<nr>"`, matching the
 * x86_64 `LinuxSyscalls` convention so the runner's classifier handles either.
 *
 * This is the arch-neutral *first brick* of the arm64 port (see
 * docs/introvirt-arm64.md): it is pure data with no architecture coupling, so
 * it compiles and is testable today, ahead of the core arm64 backend. Phase 4
 * (the arm64 Linux guest model) consumes it from the syscall decoder, exactly
 * as the x86_64 path consumes `LinuxSyscalls`.
 */
class LinuxSyscallsArm64 {
  public:
    /**
     * @brief Name for an AArch64 syscall number (e.g. 56 -> "openat"), or
     *        "sys_<nr>" if not in the curated table.
     */
    static std::string name(uint32_t number);
};

} // namespace linux_guest
} // namespace introvirt
