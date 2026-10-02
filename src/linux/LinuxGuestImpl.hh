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

#include "core/domain/GuestImpl.hh"
#include "linux/kernel/LinuxKernelImpl.hh"

#include <introvirt/linux/LinuxGuest.hh>

#include <memory>
#include <optional>

namespace introvirt {
namespace linux_guest {

/**
 * @brief Concrete Linux guest (x86_64), implementing Guest + GuestImpl.
 *
 * Mirrors windows::WindowsGuestImpl. The constructor builds the
 * LinuxKernelImpl (which performs detection) and re-raises any failure as a
 * GuestDetectionException so DomainImpl::detect_guest() can fall through.
 *
 * The event-handling surface (filter_event), memory injection (allocate /
 * guest_free) and the page-fault / current-thread resolution are stubbed
 * for now — see docs/introvirt-linux-port.md. They are not reached yet
 * because the detect_guest() Linux branch is wired in a later increment,
 * once LinuxEventImpl exists. This class is compiled (and checked by the
 * introvirt-build CI gate) ahead of that wiring.
 */
class LinuxGuestImpl final : public LinuxGuest, public GuestImpl {
  public:
    // --- Guest ---
    OS os() const override;
    bool x64() const override;
    guest_ptr<void> allocate(size_t& region_size, bool executable = false) override;
    void guest_free(const guest_ptr<void>& ptr, size_t region_size) override;
    bool page_in(Event& event, uint64_t virtual_address) override;
    GuestImpl& impl() override { return *this; }
    const GuestImpl& impl() const override { return *this; }

    // --- GuestImpl ---
    std::unique_ptr<Event> filter_event(std::unique_ptr<HypervisorEvent>&& event) override;
    GuestPageFaultResult handle_page_fault(uint64_t virtual_address, uint64_t page_directory,
                                           uint64_t& pte) const override;
    uint64_t get_current_thread_id(const Vcpu& vcpu) const override;

    // --- LinuxGuest ---
    LinuxKernel& kernel() override;
    const LinuxKernel& kernel() const override;
    Domain& domain() override;
    const Domain& domain() const override;

    explicit LinuxGuestImpl(Domain& domain);

  private:
    Domain* domain_;
    std::optional<LinuxKernelImpl> kernel_;
};

} // namespace linux_guest
} // namespace introvirt
