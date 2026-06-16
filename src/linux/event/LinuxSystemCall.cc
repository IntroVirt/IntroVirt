/*
 * Copyright 2026 SecTepe.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *         http://www.apache.org/licenses/LICENSE-2.0
 */
#include "LinuxSystemCall.hh"

#include "core/event/HypervisorEvent.hh"
#include "linux/kernel/LinuxSyscalls.hh"

#include <introvirt/core/arch/x86/Registers.hh>
#include <introvirt/core/domain/Vcpu.hh>
#include <introvirt/core/event/Event.hh>
#include <introvirt/core/exception/TraceableException.hh>
#include <introvirt/core/memory/guest_ptr.hh>
#include <introvirt/util/json/json.hh>

#include <cstring>
#include <ostream>
#include <unordered_map>

namespace introvirt {
namespace linux_guest {

namespace {

// --- flag/enum decoders (x86_64 Linux uapi constants, version-stable) ------

void append_flag(std::string& out, const char* name) {
    if (!out.empty())
        out += '|';
    out += name;
}

std::string decode_open_flags(uint64_t f) {
    std::string s;
    switch (f & 0x3) { // access mode (low 2 bits)
    case 0: append_flag(s, "O_RDONLY"); break;
    case 1: append_flag(s, "O_WRONLY"); break;
    case 2: append_flag(s, "O_RDWR"); break;
    default: break;
    }
    const std::pair<uint64_t, const char*> bits[] = {
        {0x40, "O_CREAT"},   {0x80, "O_EXCL"},      {0x200, "O_TRUNC"},
        {0x400, "O_APPEND"}, {0x800, "O_NONBLOCK"}, {0x4000, "O_DIRECT"},
        {0x10000, "O_DIRECTORY"}, {0x20000, "O_NOFOLLOW"}, {0x80000, "O_CLOEXEC"},
    };
    for (const auto& b : bits)
        if (f & b.first)
            append_flag(s, b.second);
    return s;
}

std::string decode_prot(uint64_t p) {
    if (p == 0)
        return "PROT_NONE";
    std::string s;
    if (p & 0x1) append_flag(s, "PROT_READ");
    if (p & 0x2) append_flag(s, "PROT_WRITE");
    if (p & 0x4) append_flag(s, "PROT_EXEC");
    return s;
}

std::string decode_mmap_flags(uint64_t f) {
    std::string s;
    const std::pair<uint64_t, const char*> bits[] = {
        {0x1, "MAP_SHARED"}, {0x2, "MAP_PRIVATE"}, {0x10, "MAP_FIXED"},
        {0x20, "MAP_ANONYMOUS"},
    };
    for (const auto& b : bits)
        if (f & b.first)
            append_flag(s, b.second);
    return s;
}

std::string decode_socket_domain(uint64_t d) {
    switch (d) {
    case 1: return "AF_UNIX";
    case 2: return "AF_INET";
    case 10: return "AF_INET6";
    case 16: return "AF_NETLINK";
    case 17: return "AF_PACKET";
    default: return {};
    }
}

std::string decode_socket_type(uint64_t t) {
    switch (t & 0xff) { // low byte; SOCK_CLOEXEC/NONBLOCK live in the high bits
    case 1: return "SOCK_STREAM";
    case 2: return "SOCK_DGRAM";
    case 3: return "SOCK_RAW";
    case 5: return "SOCK_SEQPACKET";
    default: return {};
    }
}

int path_arg_index(const std::string& name) {
    static const std::unordered_map<std::string, int> kPathArg = {
        {"open", 0},      {"creat", 0},     {"stat", 0},     {"lstat", 0},
        {"access", 0},    {"chdir", 0},     {"chmod", 0},    {"chown", 0},
        {"lchown", 0},    {"mkdir", 0},     {"rmdir", 0},    {"unlink", 0},
        {"readlink", 0},  {"truncate", 0},  {"execve", 0},   {"chroot", 0},
        {"mknod", 0},     {"statfs", 0},    {"link", 0},     {"symlink", 1},
        {"openat", 1},    {"openat2", 1},   {"newfstatat", 1}, {"unlinkat", 1},
        {"mkdirat", 1},   {"mknodat", 1},   {"fchownat", 1}, {"fchmodat", 1},
        {"faccessat", 1}, {"faccessat2", 1}, {"readlinkat", 1}, {"execveat", 1},
        {"statx", 1},
    };
    const auto it = kPathArg.find(name);
    return it == kPathArg.end() ? -1 : it->second;
}

std::string read_guest_cstr(const Vcpu& vcpu, uint64_t address, size_t max = 256) {
    if (address == 0)
        return {};
    try {
        guest_ptr<char[]> ptr(vcpu, address, max);
        const char* data = ptr.get();
        return std::string(data, ::strnlen(data, max));
    } catch (const TraceableException&) {
        return {}; // unmapped / unreadable — best-effort
    }
}

} // namespace

LinuxSystemCall::LinuxSystemCall(HypervisorEvent& event) {
    const auto& registers = event.vcpu().registers();
    number_ = static_cast<uint32_t>(registers.rax());
    name_ = LinuxSyscalls::name(number_);

    // x86_64 syscall arg registers, in order.
    args_[0] = registers.rdi();
    args_[1] = registers.rsi();
    args_[2] = registers.rdx();
    args_[3] = registers.r10();
    args_[4] = registers.r8();
    args_[5] = registers.r9();

    const int path_index = path_arg_index(name_);
    if (path_index >= 0) {
        path_ = read_guest_cstr(event.vcpu(), args_[path_index]);
        has_path_ = !path_.empty();
    }

    // Typed flag/enum decoding for the common, high-signal syscalls.
    if (name_ == "open")
        decoded_.emplace_back("flags", decode_open_flags(args_[1]));
    else if (name_ == "openat")
        decoded_.emplace_back("flags", decode_open_flags(args_[2]));
    else if (name_ == "mmap") {
        decoded_.emplace_back("prot", decode_prot(args_[2]));
        decoded_.emplace_back("flags", decode_mmap_flags(args_[3]));
    } else if (name_ == "mprotect") {
        decoded_.emplace_back("prot", decode_prot(args_[2]));
    } else if (name_ == "socket") {
        auto domain = decode_socket_domain(args_[0]);
        auto type = decode_socket_type(args_[1]);
        if (!domain.empty())
            decoded_.emplace_back("domain", std::move(domain));
        if (!type.empty())
            decoded_.emplace_back("type", std::move(type));
    }
}

void LinuxSystemCall::handle_return_event(Event& event) {
    // The framework carries this handler to the return event (DomainImpl);
    // on x86_64 the syscall return value is in RAX (often a negative errno).
    return_value_ = static_cast<int64_t>(event.vcpu().registers().rax());
    has_return_ = true;
}

void LinuxSystemCall::write(std::ostream& os) const {
    // Indented so the runner's ivsyscallmon shim captures these as arguments.
    os << "    nr=" << number_;
    for (unsigned i = 0; i < 6; ++i)
        os << " arg" << i << "=0x" << std::hex << args_[i] << std::dec;
    os << '\n';
    if (has_path_)
        os << "    path=\"" << path_ << "\"\n";
    for (const auto& d : decoded_)
        os << "    " << d.first << "=" << d.second << '\n';
    if (has_return_)
        os << "    result=" << return_value_ << '\n';
}

Json::Value LinuxSystemCall::json() const {
    Json::Value result;
    result["name"] = name_;
    result["number"] = number_;
    Json::Value args(Json::arrayValue);
    for (unsigned i = 0; i < 6; ++i)
        args.append(static_cast<Json::UInt64>(args_[i]));
    result["args"] = std::move(args);
    if (has_path_)
        result["path"] = path_;
    for (const auto& d : decoded_)
        result["decoded"][d.first] = d.second;
    if (has_return_)
        result["return"] = static_cast<Json::Int64>(return_value_);
    return result;
}

} // namespace linux_guest
} // namespace introvirt
