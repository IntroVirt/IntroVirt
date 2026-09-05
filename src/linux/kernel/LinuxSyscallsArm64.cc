/*
 * Copyright 2026 SecTepe.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *         http://www.apache.org/licenses/LICENSE-2.0
 */
#include "LinuxSyscallsArm64.hh"

#include <unordered_map>

namespace introvirt {
namespace linux_guest {

std::string LinuxSyscallsArm64::name(uint32_t number) {
    // Curated, version-stable AArch64 syscall numbers from the architecture's
    // asm-generic table (include/uapi/asm-generic/unistd.h). Focused on the
    // file / network / process / exec calls that matter for behavioural
    // analysis. Note: arm64 has no bare open/fork/dup2/stat/access — the
    // *at-suffixed forms are the only ones (openat, dup3, newfstatat,
    // faccessat) — so those legacy names are deliberately absent.
    static const std::unordered_map<uint32_t, const char*> kTable = {
        {17, "getcwd"},        {23, "dup"},           {24, "dup3"},
        {25, "fcntl"},         {29, "ioctl"},         {33, "mknodat"},
        {34, "mkdirat"},       {35, "unlinkat"},      {36, "symlinkat"},
        {37, "linkat"},        {38, "renameat"},      {39, "umount2"},
        {40, "mount"},         {43, "statfs"},        {45, "truncate"},
        {46, "ftruncate"},     {48, "faccessat"},     {49, "chdir"},
        {51, "chroot"},        {52, "fchmod"},        {53, "fchmodat"},
        {54, "fchownat"},      {55, "fchown"},        {56, "openat"},
        {57, "close"},         {59, "pipe2"},         {61, "getdents64"},
        {62, "lseek"},         {63, "read"},          {64, "write"},
        {65, "readv"},         {66, "writev"},        {67, "pread64"},
        {68, "pwrite64"},      {71, "sendfile"},      {72, "pselect6"},
        {73, "ppoll"},         {78, "readlinkat"},    {79, "newfstatat"},
        {80, "fstat"},         {82, "fsync"},         {90, "capget"},
        {91, "capset"},        {93, "exit"},          {94, "exit_group"},
        {96, "set_tid_address"}, {98, "futex"},       {101, "nanosleep"},
        {117, "ptrace"},       {122, "sched_setaffinity"},
        {124, "sched_yield"},  {129, "kill"},         {130, "tkill"},
        {131, "tgkill"},       {134, "rt_sigaction"}, {135, "rt_sigprocmask"},
        {139, "rt_sigreturn"}, {153, "times"},        {157, "setsid"},
        {160, "uname"},        {165, "getrusage"},    {167, "prctl"},
        {169, "gettimeofday"}, {172, "getpid"},       {173, "getppid"},
        {174, "getuid"},       {175, "geteuid"},      {176, "getgid"},
        {177, "getegid"},      {178, "gettid"},       {179, "sysinfo"},
        {198, "socket"},       {199, "socketpair"},   {200, "bind"},
        {201, "listen"},       {202, "accept"},       {203, "connect"},
        {204, "getsockname"},  {205, "getpeername"},  {206, "sendto"},
        {207, "recvfrom"},     {208, "setsockopt"},   {209, "getsockopt"},
        {210, "shutdown"},     {211, "sendmsg"},      {212, "recvmsg"},
        {214, "brk"},          {215, "munmap"},       {216, "mremap"},
        {220, "clone"},        {221, "execve"},       {222, "mmap"},
        {223, "fadvise64"},    {226, "mprotect"},     {227, "msync"},
        {233, "madvise"},      {242, "accept4"},      {243, "recvmmsg"},
        {260, "wait4"},        {261, "prlimit64"},    {269, "sendmmsg"},
        {270, "process_vm_readv"},                    {271, "process_vm_writev"},
        {272, "kcmp"},         {277, "seccomp"},      {278, "getrandom"},
        {279, "memfd_create"}, {280, "bpf"},          {281, "execveat"},
        {285, "copy_file_range"}, {286, "preadv2"},   {287, "pwritev2"},
        {291, "statx"},        {424, "pidfd_send_signal"},
        {434, "pidfd_open"},   {435, "clone3"},       {436, "close_range"},
        {437, "openat2"},      {438, "pidfd_getfd"},  {439, "faccessat2"},
        {440, "process_madvise"},
    };

    const auto it = kTable.find(number);
    if (it != kTable.end())
        return it->second;
    return "sys_" + std::to_string(number);
}

} // namespace linux_guest
} // namespace introvirt
