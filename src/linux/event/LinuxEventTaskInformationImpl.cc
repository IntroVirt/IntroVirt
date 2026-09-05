/*
 * Copyright 2026 SecTepe.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *         http://www.apache.org/licenses/LICENSE-2.0
 */
#include "LinuxEventTaskInformationImpl.hh"

#include "linux/kernel/LinuxTask.hh"

#include <introvirt/core/arch/x86/Registers.hh>
#include <introvirt/core/domain/Domain.hh>
#include <introvirt/core/domain/Vcpu.hh>
#include <introvirt/core/exception/TraceableException.hh>
#include <introvirt/linux/LinuxGuest.hh>
#include <introvirt/linux/kernel/LinuxKernel.hh>

namespace introvirt {
namespace linux_guest {

LinuxEventTaskInformationImpl::LinuxEventTaskInformationImpl(LinuxGuest& guest, const Vcpu& vcpu) {
    // Resolve the running task via the shared per-CPU current_task resolver
    // (LinuxKernel::current_task). The same call backs get_current_thread_id,
    // so event attribution and the framework's suspend/wake syscall-return
    // keying stay consistent. Defensive: leave the zeroed placeholder on miss.
    try {
        const LinuxKernel& kernel = guest.kernel();
        const uint64_t task_address = kernel.current_task(vcpu);
        if (task_address == 0)
            return;

        // Read the task_struct fields via the KERNEL CR3, not the live vcpu
        // CR3. At a syscall-entry event the live CR3 is the user CR3 (pre
        // swapgs/SWITCH_TO_KERNEL_CR3); under KPTI it can't map the task_struct
        // (kernel memory), so pid/tgid/comm would read as garbage/fail. The
        // kernel CR3 backs the same reads `processes()` (ivprocinfo) uses.
        const LinuxTask task(kernel, guest.domain(), kernel.page_directory(), task_address);
        task_struct_address_ = task_address;
        // Linux: task_struct.tgid is the userspace PID; task_struct.pid is the
        // per-thread id. Map to the generic pid()/tid() accordingly.
        pid_ = static_cast<uint64_t>(task.tgid());
        tid_ = static_cast<uint64_t>(task.pid());
        comm_ = task.comm();
    } catch (...) {
        // Best-effort: any read failure leaves the zeroed placeholder. Catch
        // broadly so nothing escapes into the event loop and aborts the trace.
    }
}

} // namespace linux_guest
} // namespace introvirt
