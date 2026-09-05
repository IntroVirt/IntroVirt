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

#include "core/domain/DomainImpl.hh"
#include "core/domain/VcpuImpl.hh"
#include "core/event/EventImpl.hh"
#include "core/injection/RegisterGuard.hh"

#include <introvirt/core/domain/Domain.hh>
#include <introvirt/core/domain/Vcpu.hh>
#include <introvirt/core/event/Event.hh>
#include <introvirt/core/event/EventType.hh>

#include <cstdint>

namespace introvirt {
namespace linux_guest {
namespace inject {

/**
 * @brief Inject one x86_64 Linux system call into the current guest thread.
 *
 * The Linux ABI makes this much simpler than the Windows injector: the syscall
 * number goes in RAX, up to six arguments in RDI/RSI/RDX/R10/R8/R9, and the
 * result comes back in RAX (a negative value in [-4095, -1] is ``-errno``).
 * There is no SSDT index translation, no TEB LastStatus to preserve, and no
 * stack arguments for <= 6 args.
 *
 * Mechanism (mirrors ``windows::inject::SystemCallInjector``): a
 * :class:`RegisterGuard` snapshots the vCPU, we set the syscall registers and
 * force a SYSCALL with ``Vcpu::inject_syscall()``, then suspend the event until
 * the matching ``EVENT_FAST_SYSCALL_RET`` fires; RAX at the return is the
 * result. The guard restores the original registers as the call unwinds, so the
 * guest thread resumes exactly where it was.
 *
 * MUST be called from within an active event handler (so a vCPU is stopped at a
 * syscall boundary and ``current`` is the target process).
 */
class SystemCallInjector final {
  public:
    SystemCallInjector(Event& event, uint64_t syscall_number, uint64_t arg0 = 0,
                       uint64_t arg1 = 0, uint64_t arg2 = 0, uint64_t arg3 = 0,
                       uint64_t arg4 = 0, uint64_t arg5 = 0)
        : event_(event), nr_(syscall_number),
          args_{arg0, arg1, arg2, arg3, arg4, arg5} {}

    /**
     * @brief Run the injected syscall and return its result (RAX).
     * @return The raw syscall return; negative values in [-4095,-1] are -errno.
     */
    int64_t call() {
        auto& vcpu = static_cast<VcpuImpl&>(event_.vcpu());
        auto& regs = vcpu.registers();
        auto& domain = static_cast<DomainImpl&>(event_.domain());

        // Snapshot + auto-restore the vCPU around the injection.
        introvirt::inject::RegisterGuard guard(vcpu);

        // Linux x86_64 syscall ABI.
        regs.rax(nr_);
        regs.rdi(args_[0]);
        regs.rsi(args_[1]);
        regs.rdx(args_[2]);
        regs.r10(args_[3]);
        regs.r8(args_[4]);
        regs.r9(args_[5]);

        domain.start_injection(event_);
        int64_t result = 0;
        try {
            vcpu.syscall_injection_start();
            // Force a SYSCALL at the current RIP. As in KVM the RIP changes, so
            // it fires exactly once. Must not be done while already in kernel.
            vcpu.inject_syscall();

            std::unique_ptr<Event> return_event =
                event_.impl().suspend([](const Event& e) {
                    return e.type() == EventType::EVENT_FAST_SYSCALL_RET
                               ? WakeAction::ACCEPT
                               : WakeAction::PASS;
                });
            event_.impl().injection_performed(true);

            // At the return event the live vCPU RAX holds the syscall result.
            result = static_cast<int64_t>(vcpu.registers().rax());
            (void)return_event; // not needed beyond resuming the thread

        } catch (...) {
            vcpu.syscall_injection_end();
            domain.end_injection(event_);
            throw;
        }
        vcpu.syscall_injection_end();
        domain.end_injection(event_);
        return result;
    }

    /**
     * @brief Inject a syscall that never returns to the original context.
     *
     * For ``execve``: on success the kernel discards the calling thread's
     * register file and user mapping and resumes at the new image's entry point,
     * so there is no ``EVENT_FAST_SYSCALL_RET`` matching the *old* thread to wait
     * for. The normal ``call()`` would (a) block in ``suspend()`` for a return
     * event that never pairs with this injection, and (b) on unwind let the
     * ``RegisterGuard`` write the snapshot's registers back over the freshly
     * loaded new-image state — corrupting the launched program (it dies right
     * after start). So here we set up the syscall, force the SYSCALL entry, then
     * ``release()`` the guard (keep the kernel-entry registers) and return
     * WITHOUT suspending: the next ``complete_event`` resumes the vCPU straight
     * into the execve body, which runs to completion in the new image.
     *
     * @note Only meaningful for image-replacing / no-return syscalls. The result
     *       is unobservable by design; returns 0.
     */
    int64_t call_no_return() {
        auto& vcpu = static_cast<VcpuImpl&>(event_.vcpu());
        auto& regs = vcpu.registers();
        auto& domain = static_cast<DomainImpl&>(event_.domain());

        introvirt::inject::RegisterGuard guard(vcpu);

        regs.rax(nr_);
        regs.rdi(args_[0]);
        regs.rsi(args_[1]);
        regs.rdx(args_[2]);
        regs.r10(args_[3]);
        regs.r8(args_[4]);
        regs.r9(args_[5]);

        domain.start_injection(event_);
        try {
            vcpu.syscall_injection_start();
            // Emulate the SYSCALL instruction: this lands the vCPU at the kernel
            // syscall entry (LSTAR) with our rax/args in place. The body runs on
            // the next vCPU resume.
            vcpu.inject_syscall();
            event_.impl().injection_performed(true);
            // Keep the kernel-entry register state: do NOT restore the snapshot,
            // or execve's new image gets clobbered on resume.
            guard.release();
        } catch (...) {
            vcpu.syscall_injection_end();
            domain.end_injection(event_);
            throw;
        }
        vcpu.syscall_injection_end();
        domain.end_injection(event_);
        return 0;
    }

  private:
    Event& event_;
    uint64_t nr_;
    uint64_t args_[6];
};

} // namespace inject
} // namespace linux_guest
} // namespace introvirt
