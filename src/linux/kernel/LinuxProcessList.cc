/*
 * Copyright 2026 SecTepe.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *         http://www.apache.org/licenses/LICENSE-2.0
 */
#include "LinuxProcessList.hh"

#include "linux/profile/LinuxProfileImpl.hh" // LinuxProfileException

#include <introvirt/core/domain/Domain.hh>
#include <introvirt/core/exception/VirtualAddressNotPresentException.hh>
#include <introvirt/core/memory/guest_ptr.hh>
#include <introvirt/linux/kernel/LinuxKernel.hh>
#include <introvirt/linux/profile/LinuxProfile.hh>

namespace introvirt {
namespace linux_guest {

namespace {

// Upper bound on tasks walked, so a corrupt/cyclic list can't loop forever.
constexpr size_t kMaxTasks = 100000;

int64_t require_offset(const LinuxProfile& profile, const char* type, const char* member) {
    const auto off = profile.member_offset(type, member);
    if (!off)
        throw LinuxProfileException(std::string(type) + "." + member +
                                    " missing from Linux profile");
    return *off;
}

uint64_t read_ptr(const Domain& domain, uint64_t address, uint64_t page_directory) {
    guest_ptr<uint64_t> ptr(domain, address, page_directory);
    return *ptr;
}

} // namespace

LinuxProcessList::LinuxProcessList(const LinuxKernel& kernel, const Domain& domain,
                                   uint64_t page_directory)
    : kernel_(kernel), domain_(domain), page_directory_(page_directory) {}

std::vector<LinuxTask> LinuxProcessList::tasks() const {
    std::vector<LinuxTask> result;

    const LinuxProfile& profile = kernel_.profile();
    const int64_t tasks_off = require_offset(profile, "task_struct", "tasks");
    const int64_t next_off = require_offset(profile, "list_head", "next");

    // The list_head embedded in init_task is the anchor; the walk ends when
    // we come back round to it.
    const uint64_t anchor = kernel_.symbol("init_task").address() + tasks_off;

    try {
        uint64_t node = read_ptr(domain_, anchor + next_off, page_directory_);
        size_t guard = 0;
        while (node != anchor && node != 0 && guard++ < kMaxTasks) {
            const uint64_t task_address = node - tasks_off;
            result.emplace_back(kernel_, domain_, page_directory_, task_address);
            node = read_ptr(domain_, node + next_off, page_directory_);
        }
    } catch (const VirtualAddressNotPresentException&) {
        // Truncate the walk at the first unmapped node rather than fail.
    }

    return result;
}

} // namespace linux_guest
} // namespace introvirt
