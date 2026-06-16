/*
 * Copyright 2026 SecTepe.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *         http://www.apache.org/licenses/LICENSE-2.0
 */
#include "LinuxSyscalls.hh"

#include <unordered_map>

namespace introvirt {
namespace linux_guest {

std::string LinuxSyscalls::name(uint32_t number) {
    // Curated, version-stable x86_64 syscall numbers (linux/arch/x86/entry/
    // syscalls/syscall_64.tbl). Focused on the file / network / process /
    // exec calls that matter for behavioural analysis.
    static const std::unordered_map<uint32_t, const char*> kTable = {
        {0, "read"},          {1, "write"},          {2, "open"},
        {3, "close"},         {4, "stat"},           {5, "fstat"},
        {6, "lstat"},         {7, "poll"},           {8, "lseek"},
        {9, "mmap"},          {10, "mprotect"},      {11, "munmap"},
        {12, "brk"},          {13, "rt_sigaction"},  {14, "rt_sigprocmask"},
        {16, "ioctl"},        {17, "pread64"},       {18, "pwrite64"},
        {19, "readv"},        {20, "writev"},        {21, "access"},
        {22, "pipe"},         {23, "select"},        {32, "dup"},
        {33, "dup2"},         {35, "nanosleep"},     {39, "getpid"},
        {41, "socket"},       {42, "connect"},       {43, "accept"},
        {44, "sendto"},       {45, "recvfrom"},      {46, "sendmsg"},
        {47, "recvmsg"},      {48, "shutdown"},      {49, "bind"},
        {50, "listen"},       {51, "getsockname"},   {52, "getpeername"},
        {53, "socketpair"},   {54, "setsockopt"},    {55, "getsockopt"},
        {56, "clone"},        {57, "fork"},          {58, "vfork"},
        {59, "execve"},       {60, "exit"},          {61, "wait4"},
        {62, "kill"},         {63, "uname"},         {72, "fcntl"},
        {78, "getdents"},     {79, "getcwd"},        {80, "chdir"},
        {82, "rename"},       {83, "mkdir"},         {84, "rmdir"},
        {85, "creat"},        {86, "link"},          {87, "unlink"},
        {88, "symlink"},      {89, "readlink"},      {90, "chmod"},
        {91, "fchmod"},       {92, "chown"},         {101, "ptrace"},
        {102, "getuid"},      {104, "getgid"},       {105, "setuid"},
        {106, "setgid"},      {107, "geteuid"},      {108, "getegid"},
        {110, "getppid"},     {137, "statfs"},       {157, "prctl"},
        {158, "arch_prctl"},  {165, "mount"},        {166, "umount2"},
        {169, "reboot"},      {186, "gettid"},       {200, "tkill"},
        {202, "futex"},       {217, "getdents64"},   {231, "exit_group"},
        {257, "openat"},      {258, "mkdirat"},      {259, "mknodat"},
        {260, "fchownat"},    {263, "unlinkat"},     {265, "linkat"},
        {266, "symlinkat"},   {267, "readlinkat"},   {268, "fchmodat"},
        {269, "faccessat"},   {280, "utimensat"},    {288, "accept4"},
        {292, "dup3"},        {299, "recvmmsg"},     {307, "sendmmsg"},
        {310, "process_vm_readv"},                   {311, "process_vm_writev"},
        {316, "renameat2"},   {318, "getrandom"},    {319, "memfd_create"},
        {321, "bpf"},         {322, "execveat"},     {332, "statx"},
        {435, "clone3"},      {437, "openat2"},      {439, "faccessat2"},
    };

    const auto it = kTable.find(number);
    if (it != kTable.end())
        return it->second;
    return "sys_" + std::to_string(number);
}

} // namespace linux_guest
} // namespace introvirt
