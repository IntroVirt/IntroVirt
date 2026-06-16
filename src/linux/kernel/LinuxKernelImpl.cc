/*
 * Copyright 2026 SecTepe.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *         http://www.apache.org/licenses/LICENSE-2.0
 */
#include "LinuxKernelImpl.hh"

#include "linux/kernel/LinuxProcessList.hh"
#include "linux/kernel/LinuxTask.hh"

#include <introvirt/core/arch/x86/Msr.hh>
#include <introvirt/core/arch/x86/PageDirectory.hh>
#include <introvirt/core/arch/x86/Registers.hh>
#include <introvirt/core/domain/Domain.hh>
#include <introvirt/core/domain/Vcpu.hh>
#include <introvirt/core/exception/GuestDetectionException.hh>
#include <introvirt/core/exception/TraceableException.hh>
#include <introvirt/core/exception/VirtualAddressNotPresentException.hh>
#include <introvirt/core/memory/guest_ptr.hh>

#include <cstdlib>
#include <cstring>

namespace introvirt {
namespace linux_guest {

namespace {
// Read up to `max` bytes of a NUL-terminated string from the guest.
// guest_ptr<char[]> (the array form) takes a length and maps a buffer; the
// non-array guest_ptr<char> only has 1-/2-arg resets and would not compile.
std::string read_guest_cstr(const Vcpu& vcpu, uint64_t address, size_t max) {
    guest_ptr<char[]> ptr(vcpu, address, max);
    const char* data = ptr.get();
    const size_t len = ::strnlen(data, max);
    return std::string(data, len);
}

// x86_64 canonical kernel half — kernel virtual addresses sit above this.
constexpr uint64_t kKernelHalf = 0xffff800000000000ULL;
bool is_kernel_address(uint64_t address) { return address >= kKernelHalf; }
} // namespace

LinuxKernelImpl::LinuxKernelImpl(Domain& domain) : domain_(&domain) {
    // Prefer a vcpu that is currently handling an event (its registers are
    // the freshest), else fall back to vcpu 0.
    Vcpu* vcpu = &domain.vcpu(0);
    for (uint32_t i = 0; i < domain.vcpu_count(); ++i) {
        Vcpu& v = domain.vcpu(i);
        if (v.handling_event()) {
            vcpu = &v;
            break;
        }
    }

    const auto& registers = vcpu->registers();
    const uint64_t lstar = registers.msr(x86::Msr::MSR_LSTAR);
    if (lstar == 0)
        throw GuestDetectionException(domain, "MSR_LSTAR is 0 (kernel not booted yet?)");
    page_directory_ = registers.cr3();

    // The profile is selected out-of-band: the runner/operator points
    // $INTROVIRT_LINUX_PROFILE at the SecTepe ISF for this guest's kernel.
    // Without one we have no symbols, so Linux simply isn't detected here
    // (the runner's hybrid path still handles the guest).
    const char* profile_path = std::getenv("INTROVIRT_LINUX_PROFILE");
    if (profile_path == nullptr)
        throw GuestDetectionException(
            domain, "INTROVIRT_LINUX_PROFILE is unset; no Linux profile to match");

    // LinuxProfile::load throws LinuxProfileException on a broken file.
    profile_ = LinuxProfile::load(profile_path);

    const auto entry = profile_->symbol("entry_SYSCALL_64");
    if (!entry)
        throw GuestDetectionException(domain, "profile is missing entry_SYSCALL_64");

    // LSTAR is the live address of entry_SYSCALL_64; the difference from the
    // profile's link-time address is the KASLR slide applied to all symbols.
    kaslr_slide_ = static_cast<int64_t>(lstar) - static_cast<int64_t>(*entry);

    // Confirm this really is the matching Linux kernel: read linux_banner at
    // its slid address and require the canonical "Linux version " prefix.
    const auto banner_link = profile_->symbol("linux_banner");
    if (!banner_link)
        throw GuestDetectionException(domain, "profile is missing linux_banner");
    const uint64_t banner_address = *banner_link + static_cast<uint64_t>(kaslr_slide_);

    try {
        const std::string banner = read_guest_cstr(*vcpu, banner_address, 256);
        static const std::string kPrefix = "Linux version ";
        if (banner.rfind(kPrefix, 0) != 0)
            throw GuestDetectionException(
                domain, "linux_banner mismatch at slid address: '" +
                            banner.substr(0, 32) + "'");
        banner_ = banner;
        const std::string rest = banner.substr(kPrefix.size());
        release_ = rest.substr(0, rest.find(' '));
    } catch (const VirtualAddressNotPresentException&) {
        throw GuestDetectionException(domain, "linux_banner address is not mapped");
    }

    const auto text = profile_->symbol("_text");
    base_address_ = (text ? *text : 0) + static_cast<uint64_t>(kaslr_slide_);

    // Pin a STABLE kernel-mapping CR3 for event-time reads. `page_directory_`
    // so far is whatever CR3 was live at construction — fine for the detection
    // reads above, but it may be a short-lived process's CR3 that later gets
    // freed, after which event-handler kernel reads (current_task, task_struct
    // fields) fail and attribution collapses to 0:0. `init_top_pgt` (the
    // kernel's top-level page table; `init_level4_pgt`/`swapper_pg_dir` on
    // older kernels) never moves — its PHYSICAL address IS the kernel CR3.
    // Translate its VA once here and use that for every subsequent read.
    for (const char* sym : {"init_top_pgt", "init_level4_pgt"}) {
        const auto link = profile_->symbol(sym);
        if (!link)
            continue;
        try {
            const uint64_t va = *link + static_cast<uint64_t>(kaslr_slide_);
            const uint64_t pa = domain.page_directory().translate(va, page_directory_);
            if (pa != 0) {
                page_directory_ = pa & ~0xfffULL; // CR3 is page-aligned
                break;
            }
        } catch (const TraceableException&) {
            // Couldn't translate — keep the construction-time CR3.
        }
    }
}

const std::string& LinuxKernelImpl::release() const { return release_; }
const std::string& LinuxKernelImpl::banner() const { return banner_; }
uint64_t LinuxKernelImpl::base_address() const { return base_address_; }
int64_t LinuxKernelImpl::kaslr_slide() const { return kaslr_slide_; }
const LinuxProfile& LinuxKernelImpl::profile() const { return *profile_; }
uint64_t LinuxKernelImpl::page_directory() const { return page_directory_; }

guest_ptr<void> LinuxKernelImpl::symbol(const std::string& name) const {
    const auto link = profile_->symbol(name);
    if (!link)
        throw GuestDetectionException(*domain_, "symbol not in Linux profile: " + name);
    const uint64_t address = *link + static_cast<uint64_t>(kaslr_slide_);
    return guest_ptr<void>(*domain_, address, page_directory_);
}

std::vector<LinuxProcess> LinuxKernelImpl::processes() const {
    std::vector<LinuxProcess> result;
    LinuxProcessList list(*this, *domain_, page_directory_);
    for (const LinuxTask& task : list.tasks()) {
        result.emplace_back(task.tgid(), task.pid(), task.comm(), task.address());
    }
    return result;
}

uint64_t LinuxKernelImpl::process_page_directory(uint64_t task_address) const {
    const auto mm_off = profile_->member_offset("task_struct", "mm");
    const auto pgd_off = profile_->member_offset("mm_struct", "pgd");
    const auto page_offset_base = profile_->symbol("page_offset_base");
    if (!mm_off || !pgd_off || !page_offset_base)
        return 0;

    try {
        // task_struct.mm — NULL for kernel threads (no userspace address space).
        const uint64_t mm =
            *guest_ptr<uint64_t>(*domain_, task_address + *mm_off, page_directory_);
        if (mm == 0)
            return 0;

        // mm_struct.pgd is a direct-map kernel virtual address; the CR3 value
        // is its physical address = pgd_kva - page_offset_base (the live,
        // KASLR-randomised direct-map base, read from the slid symbol).
        const uint64_t pgd_kva =
            *guest_ptr<uint64_t>(*domain_, mm + *pgd_off, page_directory_);
        const uint64_t direct_map_base = *guest_ptr<uint64_t>(
            *domain_, *page_offset_base + static_cast<uint64_t>(kaslr_slide_), page_directory_);
        if (pgd_kva <= direct_map_base)
            return 0;
        return pgd_kva - direct_map_base;
    } catch (const TraceableException&) {
        return 0;
    }
}

uint64_t LinuxKernelImpl::current_task(const Vcpu& vcpu) const {
    // `current_task` is a per-CPU pointer; its profile address is the offset
    // within the per-CPU area (no KASLR slide — that applies to absolute
    // symbols, not per-CPU offsets).
    const auto ct_off = profile_->symbol("current_task");
    if (!ct_off)
        return 0;
    const auto comm_off = profile_->member_offset("task_struct", "comm");

    const auto& registers = vcpu.registers();

    // CR3 candidates for reading the (kernel-resident) per-CPU `current_task`:
    //  1. the live vcpu CR3 — correct when the guest has NO KPTI (user CR3 maps
    //     the kernel) or the event fired after SWITCH_TO_KERNEL_CR3.
    //  2. `page_directory_` — the CR3 captured at detection, PROVEN to map the
    //     kernel (the `linux_banner` read succeeded through it). Under KPTI the
    //     live CR3 at syscall entry is the *user* CR3 and can't read kernel
    //     data, so this kernel-mapping CR3 is the fallback that actually works.
    //     (Validated on-host: with only the live CR3, attribution stayed 0:0.)
    const uint64_t pgds[] = {registers.cr3(), page_directory_};

    // The kernel per-CPU base lives in GS, but a syscall-entry event can fire
    // either side of `swapgs` — so the kernel base is in MSR_KERNEL_GS_BASE OR
    // MSR_GS_BASE. Try both; validate each candidate by requiring a printable
    // first comm byte, so a wrong base (→ a garbage pointer, or the idle/user
    // value) is rejected rather than mis-attributed.
    const uint64_t bases[] = {
        registers.msr(x86::Msr::MSR_KERNEL_GS_BASE),
        registers.msr(x86::Msr::MSR_GS_BASE),
    };
    for (const uint64_t pgd : pgds) {
        if (pgd == 0)
            continue;
        for (const uint64_t base : bases) {
            if (!is_kernel_address(base))
                continue;
            try {
                const uint64_t task = *guest_ptr<uint64_t>(*domain_, base + *ct_off, pgd);
                if (!is_kernel_address(task))
                    continue;
                if (comm_off) {
                    guest_ptr<char[]> comm(*domain_, task + *comm_off, pgd, 16);
                    const auto c0 = static_cast<unsigned char>(comm.get()[0]);
                    if (c0 <= 0x20 || c0 >= 0x7f)
                        continue; // empty/garbage comm — not a real task
                }
                return task;
            } catch (...) {
                // Read failed (page not present via this CR3, transient KVMi
                // EAGAIN, etc.) — MUST catch broadly so it can't escape into
                // the event loop; try the next base/CR3.
            }
        }
    }
    return 0;
}

} // namespace linux_guest
} // namespace introvirt
