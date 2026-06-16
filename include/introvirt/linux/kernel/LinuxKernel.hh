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

#include <introvirt/core/domain/Guest.hh> // brings OS + guest_ptr + Event
#include <introvirt/fwd.hh>
#include <introvirt/linux/kernel/LinuxProcess.hh>

#include <cstdint>
#include <string>
#include <vector>

namespace introvirt {
namespace linux_guest {

class LinuxProfile;

/**
 * @brief A representation of a live Linux kernel.
 *
 * The Linux analogue of ``nt::NtKernel``: it owns the loaded profile, the
 * resolved KASLR slide, and the kernel identity (banner / release), and it
 * resolves symbols to live guest virtual addresses.
 *
 * This is the public interface only; the implementation
 * (``LinuxKernelImpl``) does the live-guest detection (banner scan off
 * ``MSR_LSTAR``, profile match, slide computation) and is added in a later
 * increment alongside the task_struct/mm_struct walking model.
 */
class LinuxKernel {
  public:
    /**
     * @brief Kernel release string, e.g. "5.15.0-91-generic".
     */
    virtual const std::string& release() const = 0;

    /**
     * @brief Full Linux banner ("Linux version ...") read from the guest.
     */
    virtual const std::string& banner() const = 0;

    /**
     * @brief Live base address of the kernel text (``_text`` + KASLR slide).
     */
    virtual uint64_t base_address() const = 0;

    /**
     * @brief The KASLR slide (live base - profile link-time base).
     */
    virtual int64_t kaslr_slide() const = 0;

    /**
     * @brief Resolve a kernel symbol to its live guest virtual address.
     *
     * Applies the KASLR slide to the profile's link-time address.
     * @throws SymbolNotFoundException if the profile lacks the symbol.
     */
    virtual guest_ptr<void> symbol(const std::string& name) const = 0;

    /**
     * @brief The loaded symbol/layout profile.
     */
    virtual const LinuxProfile& profile() const = 0;

    /**
     * @brief Enumerate the guest's processes/tasks.
     *
     * Walks `init_task.tasks` and snapshots pid/tgid/comm per task — the
     * data an ivprocinfo Linux branch renders.
     */
    virtual std::vector<LinuxProcess> processes() const = 0;

    /**
     * @brief Physical page-directory base (CR3 value) for a process, derived
     *        from `task_struct.mm->pgd` (a direct-map KVA) via
     *        `page_offset_base`. Used to translate a virtual address in that
     *        process's address space (e.g. for ivmemwatch).
     *
     * @return the physical PGD, or 0 for a kernel thread (mm == NULL) or if it
     *         can't be resolved.
     */
    virtual uint64_t process_page_directory(uint64_t task_struct_address) const = 0;

    /**
     * @brief Resolve the running task's `task_struct` address on a vCPU.
     *
     * Reads the per-CPU `current_task` pointer via the kernel GS base. Used
     * both for event process-attribution and as the event thread id (so the
     * framework's suspend/wake syscall-return correlation keys correctly).
     *
     * @return the current task_struct address, or 0 if it can't be resolved.
     */
    virtual uint64_t current_task(const Vcpu& vcpu) const = 0;

    /**
     * @brief A CR3 that maps the kernel half of the address space.
     *
     * Captured at detection (when the `linux_banner` read — a kernel symbol —
     * succeeded through it), so it reliably maps kernel memory. Use this to
     * read kernel data (`task_struct` fields, per-CPU areas) from an event
     * handler: at a SYSCALL-entry event the live `Vcpu` CR3 is the *user* CR3
     * (pre-`swapgs`/`SWITCH_TO_KERNEL_CR3`) and under KPTI can't map kernel
     * data. Backs the same reads `symbol()`/`processes()` already use.
     */
    virtual uint64_t page_directory() const = 0;

    virtual ~LinuxKernel() = default;
};

} // namespace linux_guest
} // namespace introvirt
