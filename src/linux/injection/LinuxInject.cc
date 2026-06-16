/*
 * Copyright 2026 SecTepe.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *         http://www.apache.org/licenses/LICENSE-2.0
 */
#include "SystemCallInjector.hh"

#include <introvirt/core/domain/Vcpu.hh>
#include <introvirt/core/exception/TraceableException.hh>
#include <introvirt/core/memory/guest_ptr.hh>
#include <introvirt/linux/inject/syscall.hh>

#include <algorithm>
#include <cstring>

namespace introvirt {
namespace linux_guest {
namespace inject {

namespace {
// A Linux syscall error is a negative return in [-4095, -1].
inline bool is_error(int64_t r) { return r < 0 && r > -4096; }
inline uint64_t page_round(uint64_t n) { return (n + 0xFFFULL) & ~0xFFFULL; }
} // namespace

int64_t inject_mmap(Event& event, uint64_t addr, uint64_t length, int prot, int flags,
                    int fd, uint64_t offset) {
    return SystemCallInjector(event, nr::mmap, addr, length,
                              static_cast<uint64_t>(prot), static_cast<uint64_t>(flags),
                              static_cast<uint64_t>(static_cast<int64_t>(fd)), offset)
        .call();
}

int64_t inject_munmap(Event& event, uint64_t addr, uint64_t length) {
    return SystemCallInjector(event, nr::munmap, addr, length).call();
}

int64_t inject_openat(Event& event, int dirfd, uint64_t pathname_ptr, int flags, int mode) {
    return SystemCallInjector(event, nr::openat,
                              static_cast<uint64_t>(static_cast<int64_t>(dirfd)),
                              pathname_ptr, static_cast<uint64_t>(flags),
                              static_cast<uint64_t>(mode))
        .call();
}

int64_t inject_read(Event& event, int fd, uint64_t buf_ptr, uint64_t count) {
    return SystemCallInjector(event, nr::read, static_cast<uint64_t>(fd), buf_ptr, count).call();
}

int64_t inject_write(Event& event, int fd, uint64_t buf_ptr, uint64_t count) {
    return SystemCallInjector(event, nr::write, static_cast<uint64_t>(fd), buf_ptr, count).call();
}

int64_t inject_close(Event& event, int fd) {
    return SystemCallInjector(event, nr::close, static_cast<uint64_t>(fd)).call();
}

int64_t inject_fork(Event& event) { return SystemCallInjector(event, nr::fork).call(); }

int64_t inject_execve(Event& event, uint64_t pathname_ptr, uint64_t argv_ptr,
                      uint64_t envp_ptr) {
    // execve replaces the process image and does not return to this thread on
    // success — use the no-return injection path (no suspend-for-return, no
    // register restore). On failure the kernel resumes the caller normally; the
    // child simply continues and is reaped, which is acceptable for launch.
    return SystemCallInjector(event, nr::execve, pathname_ptr, argv_ptr, envp_ptr).call_no_return();
}

void write_bytes(Event& event, uint64_t dst, const void* src, size_t len) {
    if (len == 0)
        return;
    // Guest memory is mapped into the host; writing through .get() modifies it.
    guest_ptr<uint8_t[]> p(event.vcpu(), dst, len);
    std::memcpy(p.get(), src, len);
}

uint64_t push_string(Event& event, const std::string& data) {
    const size_t len = data.size() + 1; // include trailing NUL
    int64_t addr =
        inject_mmap(event, 0, page_round(len), kProtRead | kProtWrite,
                    kMapPrivate | kMapAnonymous | kMapPopulate, -1, 0);
    if (is_error(addr) || addr == 0)
        return 0;
    write_bytes(event, static_cast<uint64_t>(addr), data.c_str(), len);
    return static_cast<uint64_t>(addr);
}

uint64_t push_string_array(Event& event, const std::vector<std::string>& items) {
    std::vector<uint64_t> ptrs;
    ptrs.reserve(items.size() + 1);
    for (const auto& s : items) {
        uint64_t a = push_string(event, s);
        if (a == 0)
            return 0;
        ptrs.push_back(a);
    }
    ptrs.push_back(0); // NULL terminator

    const size_t bytes = ptrs.size() * sizeof(uint64_t);
    int64_t arr =
        inject_mmap(event, 0, page_round(bytes), kProtRead | kProtWrite,
                    kMapPrivate | kMapAnonymous | kMapPopulate, -1, 0);
    if (is_error(arr) || arr == 0)
        return 0;
    write_bytes(event, static_cast<uint64_t>(arr), ptrs.data(), bytes);
    return static_cast<uint64_t>(arr);
}

// ---------------------------------------------------------------- high-level

int64_t write_file(Event& event, const std::string& guest_path, const void* data, size_t len,
                   int mode) {
    const uint64_t path_ptr = push_string(event, guest_path);
    if (path_ptr == 0)
        return -1;
    const int64_t fd =
        inject_openat(event, kAtFdcwd, path_ptr, kOWronly | kOCreat | kOTrunc, mode);
    if (is_error(fd))
        return fd;

    // Stage a guest transfer buffer; copy host chunks in and inject write().
    constexpr uint64_t kChunk = 1u << 20; // 1 MiB
    const int64_t buf = inject_mmap(event, 0, page_round(kChunk), kProtRead | kProtWrite,
                                    kMapPrivate | kMapAnonymous | kMapPopulate, -1, 0);
    if (is_error(buf)) {
        inject_close(event, static_cast<int>(fd));
        return buf;
    }

    const auto* p = static_cast<const uint8_t*>(data);
    int64_t total = 0;
    while (static_cast<size_t>(total) < len) {
        const uint64_t n = std::min<uint64_t>(kChunk, len - total);
        write_bytes(event, static_cast<uint64_t>(buf), p + total, n);
        const int64_t w = inject_write(event, static_cast<int>(fd), static_cast<uint64_t>(buf), n);
        if (is_error(w) || w == 0)
            break;
        total += w;
    }

    inject_munmap(event, static_cast<uint64_t>(buf), page_round(kChunk));
    inject_close(event, static_cast<int>(fd));
    return total;
}

std::vector<uint8_t> read_file(Event& event, const std::string& guest_path, size_t max_bytes) {
    std::vector<uint8_t> out;
    const uint64_t path_ptr = push_string(event, guest_path);
    if (path_ptr == 0)
        return out;
    const int64_t fd = inject_openat(event, kAtFdcwd, path_ptr, kORdonly, 0);
    if (is_error(fd))
        return out;

    constexpr uint64_t kChunk = 1u << 20; // 1 MiB
    const int64_t buf = inject_mmap(event, 0, page_round(kChunk), kProtRead | kProtWrite,
                                    kMapPrivate | kMapAnonymous | kMapPopulate, -1, 0);
    if (is_error(buf)) {
        inject_close(event, static_cast<int>(fd));
        return out;
    }

    while (out.size() < max_bytes) {
        const uint64_t want = std::min<uint64_t>(kChunk, max_bytes - out.size());
        const int64_t r = inject_read(event, static_cast<int>(fd), static_cast<uint64_t>(buf), want);
        if (is_error(r) || r == 0)
            break;
        guest_ptr<uint8_t[]> gp(event.vcpu(), static_cast<uint64_t>(buf), static_cast<size_t>(r));
        const uint8_t* hp = gp.get();
        out.insert(out.end(), hp, hp + r);
    }

    inject_munmap(event, static_cast<uint64_t>(buf), page_round(kChunk));
    inject_close(event, static_cast<int>(fd));
    return out;
}

int64_t execve(Event& event, const std::string& path, const std::vector<std::string>& argv,
               const std::vector<std::string>& envp) {
    const uint64_t path_ptr = push_string(event, path);
    const uint64_t argv_ptr = push_string_array(event, argv);
    const uint64_t envp_ptr = push_string_array(event, envp);
    if (path_ptr == 0 || argv_ptr == 0 || envp_ptr == 0)
        return -1;
    return inject_execve(event, path_ptr, argv_ptr, envp_ptr);
}

} // namespace inject
} // namespace linux_guest
} // namespace introvirt
