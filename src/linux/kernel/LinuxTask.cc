/*
 * Copyright 2026 SecTepe.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *         http://www.apache.org/licenses/LICENSE-2.0
 */
#include "LinuxTask.hh"

#include "linux/profile/LinuxProfileImpl.hh" // LinuxProfileException

#include <introvirt/core/domain/Domain.hh>
#include <introvirt/core/memory/guest_ptr.hh>
#include <introvirt/linux/kernel/LinuxKernel.hh>
#include <introvirt/linux/profile/LinuxProfile.hh>

#include <cstring>

namespace introvirt {
namespace linux_guest {

namespace {
template <typename T>
T read_scalar(const Domain& domain, uint64_t address, uint64_t page_directory) {
    guest_ptr<T> ptr(domain, address, page_directory);
    return *ptr;
}
} // namespace

LinuxTask::LinuxTask(const LinuxKernel& kernel, const Domain& domain, uint64_t page_directory,
                     uint64_t task_address)
    : kernel_(kernel), domain_(domain), page_directory_(page_directory),
      task_address_(task_address) {}

int64_t LinuxTask::offset(const char* member) const {
    const auto off = kernel_.profile().member_offset("task_struct", member);
    if (!off)
        throw LinuxProfileException(std::string("task_struct.") + member +
                                    " missing from Linux profile");
    return *off;
}

int32_t LinuxTask::pid() const {
    return read_scalar<int32_t>(domain_, task_address_ + offset("pid"), page_directory_);
}

int32_t LinuxTask::tgid() const {
    return read_scalar<int32_t>(domain_, task_address_ + offset("tgid"), page_directory_);
}

uint64_t LinuxTask::mm() const {
    return read_scalar<uint64_t>(domain_, task_address_ + offset("mm"), page_directory_);
}

std::string LinuxTask::comm() const {
    // task_struct.comm is char[TASK_COMM_LEN] (16), NUL-padded.
    static constexpr size_t kCommLen = 16;
    guest_ptr<char[]> ptr(domain_, task_address_ + offset("comm"), page_directory_, kCommLen);
    const char* data = ptr.get();
    return std::string(data, ::strnlen(data, kCommLen));
}

} // namespace linux_guest
} // namespace introvirt
