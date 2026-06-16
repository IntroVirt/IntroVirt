/*
 * Copyright 2026 SecTepe.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *         http://www.apache.org/licenses/LICENSE-2.0
 */
#include "LinuxGuestImpl.hh"

#include <introvirt/core/domain/Domain.hh>
#include <introvirt/core/event/Event.hh>
#include <introvirt/core/event/ThreadLocalEvent.hh>
#include <introvirt/core/exception/GuestDetectionException.hh>
#include <introvirt/core/exception/NotImplementedException.hh>
#include <introvirt/core/exception/TraceableException.hh>

#include "linux/event/LinuxEventImpl.hh"
#include <introvirt/linux/inject/syscall.hh>

namespace introvirt {
namespace linux_guest {

LinuxGuestImpl::LinuxGuestImpl(Domain& domain) : domain_(&domain) {
    domain.pause();
    try {
        // LinuxKernelImpl's constructor does the detection work and throws
        // a TraceableException (GuestDetectionException / LinuxProfileException)
        // if this isn't a matching Linux guest.
        kernel_.emplace(domain);
    } catch (const TraceableException& ex) {
        domain.resume();
        throw GuestDetectionException(domain, ex.what());
    }
    domain.resume();
}

OS LinuxGuestImpl::os() const { return OS::Linux; }

// x86_64 only for now; a PtrType template (32-bit) follows later.
bool LinuxGuestImpl::x64() const { return true; }

guest_ptr<void> LinuxGuestImpl::allocate(size_t& region_size, bool executable) {
    // Inject an anonymous private mmap into the current guest thread. Must run
    // inside an active event (ThreadLocalEvent) so a vCPU is stopped at a
    // syscall boundary with the target process as `current`.
    Event& event = ThreadLocalEvent::get();

    const uint64_t length = (region_size + 0xFFFULL) & ~0xFFFULL;
    int prot = inject::kProtRead | inject::kProtWrite;
    if (executable)
        prot |= inject::kProtExec;

    const int64_t result = inject::inject_mmap(
        event, 0, length, prot, inject::kMapPrivate | inject::kMapAnonymous | inject::kMapPopulate, -1, 0);

    // mmap returns -errno in [-4095, -1] on failure.
    if (result < 0 && result > -4096)
        return guest_ptr<void>();

    region_size = length;
    return guest_ptr<void>(event.vcpu(), static_cast<uint64_t>(result));
}

void LinuxGuestImpl::guest_free(const guest_ptr<void>& ptr, size_t region_size) {
    if (!ptr)
        return;
    try {
        Event& event = ThreadLocalEvent::get();
        const uint64_t length = (region_size + 0xFFFULL) & ~0xFFFULL;
        inject::inject_munmap(event, ptr.address(), length);
    } catch (const TraceableException&) {
        // Best-effort free: a failed munmap leaks guest memory but must not
        // propagate into the event loop.
    }
}

bool LinuxGuestImpl::page_in(Event& event, uint64_t virtual_address) {
    // Fault the page in by injecting a zero-length read against it. The kernel
    // touches the address to validate the buffer, paging it in; the syscall's
    // own success/failure is irrelevant. Best-effort.
    try {
        inject::inject_read(event, -1, virtual_address, 0);
        return true;
    } catch (const TraceableException&) {
        return false;
    }
}

std::unique_ptr<Event>
LinuxGuestImpl::filter_event(std::unique_ptr<HypervisorEvent>&& event) {
    return std::make_unique<LinuxEventImpl>(*this, std::move(event));
}

GuestPageFaultResult LinuxGuestImpl::handle_page_fault(uint64_t /*virtual_address*/,
                                                       uint64_t /*page_directory*/,
                                                       uint64_t& /*pte*/) const {
    // Defer to the core handler's failure path until the Linux page-table
    // walk is implemented.
    return GuestPageFaultResult::FAILURE;
}

uint64_t LinuxGuestImpl::get_current_thread_id(const Vcpu& vcpu) const {
    // The current task_struct address is a stable, per-thread unique id. The
    // framework keys its suspend/wake syscall-return correlation on this
    // (DomainImpl::suspend_event + get_current_thread_id), so returning 0 here
    // collapses every thread onto one key and double-wakes suspended events
    // (std::bad_function_call). Resolve it via the shared kernel resolver.
    return kernel_ ? kernel_->current_task(vcpu) : 0;
}

LinuxKernel& LinuxGuestImpl::kernel() { return *kernel_; }
const LinuxKernel& LinuxGuestImpl::kernel() const { return *kernel_; }
Domain& LinuxGuestImpl::domain() { return *domain_; }
const Domain& LinuxGuestImpl::domain() const { return *domain_; }

} // namespace linux_guest
} // namespace introvirt
