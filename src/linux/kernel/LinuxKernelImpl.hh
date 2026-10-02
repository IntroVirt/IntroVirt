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

#include <introvirt/linux/kernel/LinuxKernel.hh>
#include <introvirt/linux/profile/LinuxProfile.hh>

#include <cstdint>
#include <memory>
#include <string>

namespace introvirt {

class Domain;

namespace linux_guest {

/**
 * @brief Concrete LinuxKernel: detection + symbol resolution.
 *
 * Detection (in the constructor, throwing GuestDetectionException on miss):
 *   1. read MSR_LSTAR — the live address of entry_SYSCALL_64;
 *   2. load the profile named by $INTROVIRT_LINUX_PROFILE;
 *   3. KASLR slide = LSTAR - profile("entry_SYSCALL_64");
 *   4. confirm it's really Linux by reading `linux_banner` at its slid
 *      address and checking the "Linux version " prefix;
 *   5. parse the release out of the banner.
 *
 * x86_64 only for now (no PtrType template yet) — see
 * docs/introvirt-linux-port.md.
 *
 * NOTE: the constructor is not yet reached in production — the
 * DomainImpl::detect_guest() Linux branch is wired in a later increment,
 * once LinuxEventImpl exists. This unit is built (and compile-checked by the
 * introvirt-build CI gate) ahead of that.
 */
class LinuxKernelImpl final : public LinuxKernel {
  public:
    const std::string& release() const override;
    const std::string& banner() const override;
    uint64_t base_address() const override;
    int64_t kaslr_slide() const override;
    guest_ptr<void> symbol(const std::string& name) const override;
    const LinuxProfile& profile() const override;
    std::vector<LinuxProcess> processes() const override;
    uint64_t process_page_directory(uint64_t task_struct_address) const override;
    uint64_t current_task(const Vcpu& vcpu) const override;
    uint64_t page_directory() const override;

    explicit LinuxKernelImpl(Domain& domain);

  private:
    Domain* domain_;
    std::unique_ptr<LinuxProfile> profile_;
    int64_t kaslr_slide_ = 0;
    uint64_t base_address_ = 0;
    uint64_t page_directory_ = 0;
    std::string release_;
    std::string banner_;
};

} // namespace linux_guest
} // namespace introvirt
