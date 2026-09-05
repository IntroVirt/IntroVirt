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

/**
 * @file syscall.hh
 * @brief Public x86_64 Linux syscall-injection API.
 *
 * The injection primitive (``SystemCallInjector``) is internal; these free
 * functions are the public surface the ``iv*`` tools (and the runner) use to
 * drop/read guest files and launch processes. All MUST be called from within an
 * active event handler (a vCPU stopped at a syscall boundary, with the target
 * process as ``current``).
 */

#include <introvirt/core/fwd.hh>

#include <cstddef>
#include <cstdint>
#include <string>
#include <vector>

namespace introvirt {
namespace linux_guest {
namespace inject {

// x86_64 Linux syscall numbers (stable guest ABI).
namespace nr {
constexpr uint64_t read = 0;
constexpr uint64_t write = 1;
constexpr uint64_t open = 2;
constexpr uint64_t close = 3;
constexpr uint64_t lseek = 8;
constexpr uint64_t mmap = 9;
constexpr uint64_t munmap = 11;
constexpr uint64_t fork = 57;
constexpr uint64_t execve = 59;
constexpr uint64_t openat = 257;
} // namespace nr

// mmap prot/flags + open flags (guest ABI). 'k'-prefixed to avoid clashing with
// the host's <sys/mman.h>/<fcntl.h> macros (which would mangle these names).
constexpr int kProtRead = 0x1;
constexpr int kProtWrite = 0x2;
constexpr int kProtExec = 0x4;
constexpr int kMapPrivate = 0x2;
constexpr int kMapAnonymous = 0x20;
// Pre-fault the mapping at mmap() time. Without it an anonymous mmap is
// demand-paged: the kernel returns a VA but maps no physical page until the
// guest first touches it — so an immediate injected write_bytes() to that VA
// hits VirtualAddressNotPresentException (the execve push_string failure in
// the forked-child context). MAP_POPULATE makes the page present on return.
constexpr int kMapPopulate = 0x8000;
constexpr int kORdonly = 0x0;
constexpr int kOWronly = 0x1;
constexpr int kOCreat = 0x40;
constexpr int kOTrunc = 0x200;
constexpr int kAtFdcwd = -100;

// --- low-level: each returns the raw syscall result (RAX; -errno on error) ---
int64_t inject_mmap(Event& event, uint64_t addr, uint64_t length, int prot, int flags,
                    int fd, uint64_t offset);
int64_t inject_munmap(Event& event, uint64_t addr, uint64_t length);
int64_t inject_openat(Event& event, int dirfd, uint64_t pathname_ptr, int flags, int mode);
int64_t inject_read(Event& event, int fd, uint64_t buf_ptr, uint64_t count);
int64_t inject_write(Event& event, int fd, uint64_t buf_ptr, uint64_t count);
int64_t inject_close(Event& event, int fd);
int64_t inject_fork(Event& event);
int64_t inject_execve(Event& event, uint64_t pathname_ptr, uint64_t argv_ptr, uint64_t envp_ptr);

// --- argument marshaling into guest memory ----------------------------------
void write_bytes(Event& event, uint64_t dst, const void* src, size_t len);
uint64_t push_string(Event& event, const std::string& data);
uint64_t push_string_array(Event& event, const std::vector<std::string>& items);

// --- high-level helpers the tools call --------------------------------------

/**
 * @brief Write host bytes to a guest file (openat O_CREAT|O_WRONLY|O_TRUNC →
 *        write loop → close). Returns bytes written, or a negative -errno.
 */
int64_t write_file(Event& event, const std::string& guest_path, const void* data, size_t len,
                   int mode = 0644);

/**
 * @brief Read a guest file into a host buffer (openat O_RDONLY → read loop →
 *        close), up to ``max_bytes``. Throws on open failure.
 */
std::vector<uint8_t> read_file(Event& event, const std::string& guest_path, size_t max_bytes);

/**
 * @brief Marshal argv/envp + path into guest memory and inject execve.
 *        Replaces the current process image — call in a child/victim context.
 *        Returns the execve result (only returns at all on failure: -errno).
 */
int64_t execve(Event& event, const std::string& path, const std::vector<std::string>& argv,
               const std::vector<std::string>& envp);

} // namespace inject
} // namespace linux_guest
} // namespace introvirt
