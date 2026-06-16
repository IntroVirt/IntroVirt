/*
 * Copyright 2021 Assured Information Security, Inc.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *         http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */
#pragma once

#include "core/domain/DomainImpl.hh"
#include "core/domain/VcpuImpl.hh"
#include "core/event/EventImpl.hh"
#include "core/injection/RegisterGuard.hh"
#include "windows/WindowsGuestImpl.hh"

#include <introvirt/core/breakpoint/Breakpoint.hh>
#include <introvirt/core/domain/Domain.hh>
#include <introvirt/core/domain/Vcpu.hh>
#include <introvirt/core/event/Event.hh>
#include <introvirt/core/exception/InvalidMethodException.hh>
#include <introvirt/core/exception/SystemCallInjectionException.hh>
#include <introvirt/core/exception/VirtualAddressNotPresentException.hh>
#include <introvirt/core/injection/system_call.hh>
#include <introvirt/fwd.hh>
#include <introvirt/windows/event/WindowsEvent.hh>
#include <introvirt/windows/kernel/nt/const/NTSTATUS.hh>
#include <introvirt/windows/kernel/nt/syscall/NtDeleteFile.hh>
#include <introvirt/windows/kernel/nt/types/TEB.hh>
#include <introvirt/windows/kernel/nt/types/objects/THREAD.hh>

#include <boost/algorithm/string.hpp>
#include <log4cxx/logger.h>

#include <cassert>
#include <cstdint>
#include <cstdio>
#include <optional>

namespace introvirt {
namespace windows {
namespace inject {

extern thread_local std::optional<nt::NTSTATUS> LastStatusValueInject;

static log4cxx::LoggerPtr
    syscall_injector_logger(log4cxx::Logger::getLogger("introvirt.win.inject.SystemCallInjector"));

template <typename PtrType>
class SystemCallInjector final {
  public:
    /**
     * @brief Sleep the current thread until the system call returns
     */
    void call(WindowsSystemCall& handler) {
        auto& vcpu = static_cast<VcpuImpl&>(event_.vcpu());
        auto& regs = vcpu.registers();

        // Lock the thread affinity
        auto& thread = static_cast<WindowsEvent&>(event_).task().pcr().CurrentThread();
        const uint64_t desired_affinity = (1u << event_.vcpu().id());
        const auto original_affinity = thread.Affinity();
        const auto original_user_affinity = thread.UserAffinity();
        const auto original_ideal_processor = thread.IdealProcessor();
        const auto original_user_ideal_processor = thread.UserIdealProcessor();

        // SECTEPE: the hard-affinity pin (writing KTHREAD.Affinity /
        // KTHREAD.UserAffinity to a single-vcpu mask in live guest memory) is
        // what deadlocks a heavy, blocking, cross-thread syscall such as
        // NtCreateUserProcess on Win11.
        //
        // Why the pin hangs the heavy syscall but not a trivial one:
        //   * start_injection() does NOT pause the other vcpus for a
        //     FAST_SYSCALL injection (only INT3/MEM_ACCESS breakpoint
        //     injections pause peers — see DomainImpl::start_injection). So
        //     while the hijacked thread runs the injected syscall on this vcpu,
        //     the other vcpu(s) keep executing guest code, including the kernel
        //     scheduler.
        //   * NtDeleteFile (and the other trivial calls) complete entirely
        //     inside the syscall with no reschedule / no cross-processor wait,
        //     so a bogus single-cpu affinity mask is never consulted before the
        //     call returns: it SYSRETs fine.
        //   * NtCreateUserProcess is long and blocking: it waits on the
        //     PspCreateThread/section/IO paths, takes resources, and crucially
        //     touches per-processor scheduler state and may need to be
        //     rescheduled / have work run on another processor. With the hard
        //     KTHREAD.Affinity clamped to exactly this one vcpu, the guest
        //     scheduler can no longer migrate or wake the thread the way the
        //     create path expects; the thread is left blocked in the kernel and
        //     never SYSRETs (INJ=11 / RET=10) -> hang / -T timeout. The injector
        //     is then stuck in suspend() waiting for a FAST_SYSCALL_RET that the
        //     guest will never produce.
        //   * On Win10 19045 the same clamp happens to be tolerated by that
        //     build's create/scheduler path, so Win10 works WITH the pin and we
        //     must NOT regress it.
        //
        // The differentiator is purely the scheduler clamp interacting with the
        // Win11 heavy-create path, NOT the byte layout of KTHREAD.Affinity: that
        // field is a KAFFINITY_EX structure on both Win10 and Win11 x64 and the
        // 8-byte get()/set() round-trips it identically on both, so it cannot
        // explain why only Win11 hangs. (We still capture the original 8 bytes
        // and write the exact same value back on restore on every OS, so no new
        // corruption is introduced regardless.)
        //
        // Fix: branch on the build number. Pre-22000 (Win10 and earlier) keeps
        // the proven hard-affinity pin so the working path is unchanged.
        // 22000+ (Win11) skips the hard Affinity/UserAffinity clamp and only
        // sets the *soft* IdealProcessor / UserIdealProcessor scheduling hint
        // (advisory: the scheduler prefers this cpu but is still free to migrate
        // / wake the thread, so the heavy syscall can complete and SYSRET).
        const uint16_t build_number = guest_.kernel().NtBuildNumber();
        const bool win11_or_newer = (build_number >= 22000);

        if (win11_or_newer) {
            // Win11: advisory soft hint only, no hard Affinity/UserAffinity
            // clamp, so the guest scheduler can still migrate/wake the thread
            // and the heavy NtCreateUserProcess can complete and SYSRET.
            thread.IdealProcessor(event_.vcpu().id());
            thread.UserIdealProcessor(event_.vcpu().id());
        } else {
            // Win10 and earlier: keep the original, proven hard pin.
            thread.Affinity(desired_affinity);
            thread.UserAffinity(desired_affinity);
            thread.IdealProcessor(event_.vcpu().id());
            thread.UserIdealProcessor(event_.vcpu().id());
        }

        // Save the original LastStatusValue so we can restore it later
        auto* teb = thread.Teb();
        // TODO: What happens if Teb is null?

        nt::NTSTATUS original_laststatus;
        if (teb)
            original_laststatus = teb->LastStatusValue();

        static_cast<DomainImpl&>(event_.domain()).start_injection(event_);

        std::unique_ptr<Event> return_event;
        try {
            // Wait for the return event
            vcpu.syscall_injection_start();

            // SECTEPE: return-RIP-aware wake matching.
            //
            // On Win11 a >4-argument syscall (e.g. NtCreateUserProcess) whose
            // stack is not fully paged in triggers verify_stack_present(), which
            // injects a NESTED NtDeleteFile syscall to fault the stack in. The
            // nesting is SYNCHRONOUS on one worker thread: the inner NtDeleteFile
            // injector runs entirely inside the outer call's begin_syscall() ->
            // verify_stack_present(), i.e. the inner ctor + inner call() +
            // inner suspend()/wake() all complete BEFORE the outer ever reaches
            // this suspend(). Both injectors obtain the SAME Event via
            // ThreadLocalEvent::get(), so they share one EventImplTpl
            // (check_wakeup_/cv_) and, for the pure nested case, the per-thread
            // suspended_events_ multimap holds exactly ONE entry at each return.
            //
            // The hazard the generic "any FAST_SYSCALL_RET => ACCEPT" lambda
            // caused: that single shared waiter accepts the FIRST FAST_SYSCALL_RET
            // seen for the thread, even a foreign/early one. The inner waiter
            // could consume the wrong return (or, when two different worker
            // threads inject on the same guest KTHREAD and the map genuinely
            // holds two entries for the tid, the outer waiter could swallow the
            // inner's return). Either way verify_stack_present() never returns
            // and the session deadlocks / -T times out.
            //
            // Fix: each injection only accepts the return whose userland return
            // RIP equals the return address captured for ITS OWN injection point.
            // For SYSCALL the hardware leaves the return address in RCX at kernel
            // entry (captured in begin_syscall, after inject_syscall()). For
            // SYSENTER the saved userland rip is written to the new stack frame
            // (captured in begin_sysenter). On the matching SYSRET/SYSEXIT the
            // guest is back at that userland address, so event.registers().rip()
            // equals expected_return_rip_. A return that is not for THIS injection
            // PASSes (EventImplTpl::wake only moves the event on ACCEPT, so the
            // event is left intact for the filter_event loop / a later waiter).
            // This is the same proven shape as the rsp-based hook_return
            // correlation in DomainImpl::filter_event. Correctness does NOT depend
            // on the unordered_multimap's equal-key iteration order.
            //
            // Defensive fallback: if we somehow failed to capture an expected RIP
            // (expected_return_rip_ is unset), fall back to the original generic
            // behaviour so a single, non-nested injection still wakes.
            const std::optional<uint64_t> expected_return_rip = expected_return_rip_;
            return_event =
                event_.impl().suspend([expected_return_rip](const introvirt::Event& event) {
                    if (event.type() == EventType::EVENT_FAST_SYSCALL_RET) {
                        if (!expected_return_rip ||
                            event.vcpu().registers().rip() == *expected_return_rip) {
                            return WakeAction::ACCEPT;
                        }
                        // A FAST_SYSCALL_RET for this thread but a different
                        // injection point (e.g. the inner NtDeleteFile return
                        // arriving while a different waiter is offered the event
                        // first, or the kernel running other work in the context
                        // of the suspended thread). Let it PASS so the loop
                        // offers it to the matching suspended injection. Mirrors
                        // the hook_return rsp-mismatch TRACE in DomainImpl.
                        LOG4CXX_TRACE(syscall_injector_logger,
                                      "Incorrect return rip: 0x"
                                          << std::hex << event.vcpu().registers().rip()
                                          << " Wanted 0x" << *expected_return_rip);
                        return WakeAction::PASS;
                    }
                    return WakeAction::PASS;
                });
            event_.impl().injection_performed(true);

        } catch (...) {
            // Duplicated because c++ doesn't have 'finally'
            vcpu.syscall_injection_end();
            static_cast<DomainImpl&>(event_.domain()).end_injection(event_);

            if (teb) {
                // Update the injection laststatus values
                LastStatusValueInject.emplace(teb->LastStatusValue());

                // Restore the original values
                teb->LastStatusValue(original_laststatus);
            }

            // Restore the thread affinity
            thread.Affinity(original_affinity);
            thread.UserAffinity(original_user_affinity);
            thread.IdealProcessor(original_ideal_processor);
            thread.UserIdealProcessor(original_user_ideal_processor);

            if (original_cs_) {
                LOG4CXX_DEBUG(syscall_injector_logger, "Restoring original CS");
                regs.cs(*original_cs_);
            }

            throw;
        }

        vcpu.syscall_injection_end();
        static_cast<DomainImpl&>(event_.domain()).end_injection(event_);

        if (teb) {
            // Update the injection laststatus values
            LastStatusValueInject.emplace(teb->LastStatusValue());

            // Restore the original values
            teb->LastStatusValue(original_laststatus);
        }

        // Restore the thread affinity
        thread.Affinity(original_affinity);
        thread.UserAffinity(original_user_affinity);
        thread.IdealProcessor(original_ideal_processor);
        thread.UserIdealProcessor(original_user_ideal_processor);

        if (original_cs_) {
            LOG4CXX_DEBUG(syscall_injector_logger, "Restoring original CS");
            regs.cs(*original_cs_);
        }

        handler.handle_return_event(*return_event);

        LOG4CXX_DEBUG(syscall_injector_logger, "System call completed");
    }

    uint64_t stack_pointer() const { return rsp_; }

    SystemCallInjector(Event& event, SystemCallIndex index, unsigned int argument_count,
                       unsigned int additional_stack)
        : event_(static_cast<WindowsEvent&>(event)), guest_(event_.guest()) {
        introvirt_assert(event.os_type() == OS::Windows, "");

        auto& vcpu = event_.vcpu();
        auto& regs = vcpu.registers();

        // Set the VCPU to the correct call number
        const uint32_t callNumber = guest_.syscalls().native(index);
        if (unlikely(callNumber == 0xFFFFFFFF)) {
            throw SystemCallInjectionException("Guest does not support " + to_string(index));
        }

        guard_.emplace(event.vcpu());

        regs.rax(callNumber);

        if constexpr (std::is_same_v<PtrType, uint64_t>) {
            // 64-Bit mode

            // Get the current code segment
            auto cs = regs.cs();
            if (!cs.long_mode()) {
                // Processor is in WoW64 (32-bit) mode, jump us back to 64-bit mode
                x86::SegmentSelector sel(0x33);
                x86::Segment seg(sel, 0x0, 0x0, 0xFB, true, 3, false, true, true, false, false);
                original_cs_.emplace(cs);
                regs.cs(seg);
            }

            begin_syscall(argument_count, additional_stack);
        } else {
            // 32-Bit mode
            begin_sysenter(argument_count, additional_stack);
        }

        LOG4CXX_DEBUG(syscall_injector_logger, "Preparing to inject " << index << " into ["
                                                                      << event.task().pid() << ':'
                                                                      << event.task().tid() << "]");
    }

  private:
    void verify_stack_present(uint64_t stack_bottom, uint64_t stack_top) {
        const PtrType first_page = stack_bottom & ~(0xFFFULL);
        const PtrType last_page = stack_top & ~(0xFFFULL);
        PtrType i = last_page;
        do {
            auto& vcpu = event_.vcpu();

            try {
                // Make sure the page is accessible
                guest_ptr<uint8_t> p(vcpu, i);
            } catch (VirtualAddressNotPresentException& ex) {
                LOG4CXX_DEBUG(syscall_injector_logger,
                              "Stack " << ex.virtual_address()
                                       << " not paged in while injecting system call, fixing...");

                // Try to do a hack where we get the kernel to page in the stack for us
                // The call to NtLoadDriver doesn't succeed. We just want it to read some memory.

                if constexpr (std::is_same_v<PtrType, uint32_t>) {
                    // On x64 we don't need any stack space to call NtDeleteFile.
                    // On x86 we need 12 bytes of stack to call NtDeleteFile.
                    // Return address, return stack, and the argument.
                    if (i == last_page || (stack_top & 0xFFF) < 12) {
                        // If we're on the top page, then we don't have ANY room.
                        // If we're not, and we still don't have 12 bytes available,
                        // we can't even inject this one-argument call.
                        // TODO: Something clever
                        throw;
                    }
                }

                auto result =
                    introvirt::inject::system_call<nt::NtDeleteFile>(guest_ptr<void>(vcpu, i));
                LOG4CXX_DEBUG(syscall_injector_logger,
                              "Paged in stack via NtDeleteFile hack: " << result);

                // Okay we should be paged in!
            }
            i -= 0x1000;
        } while (i >= first_page);
    }

    void begin_sysenter(unsigned int arg_count, unsigned int additional_stack) {
        auto& vcpu = event_.vcpu();
        auto& regs = vcpu.registers();
        uint64_t rip;

        /*
         * Inject a SYSENTER instruction.
         *
         * Before executing SYSENTER, Windows sets EDX to the current ESP value.
         * We need to make sure that the return address exists on at EDX.
         */

        // Move the stack backwards enough to hold our arguments plus the return address
        const unsigned int stack_offset = (arg_count + 2) * sizeof(uint32_t);

        switch (event_.type()) {
        case EventType::EVENT_FAST_SYSCALL:
            verify_stack_present(regs.rdx() - stack_offset - additional_stack, regs.rdx());
            break;
        case EventType::EVENT_FAST_SYSCALL_RET:
        case EventType::EVENT_EXCEPTION:
            verify_stack_present(regs.rsp() - stack_offset - additional_stack, regs.rsp());
            break;
        }

        // Force a SYSENTER in the guest
        // This works even if we're already in an EVENT_FAST_SYSCALL.
        // In KVM, since the RIP changes, it won't happen twice.
        // It will not work if the VCPU is already in the kernel, though!
        // For example, if we do this in a CR3 write event the guest will die.
        vcpu.inject_sysenter();

        switch (event_.type()) {
        case EventType::EVENT_FAST_SYSCALL:
            // SYSENTER has already been triggered
            // Get the original return address from the stack
            rip = *guest_ptr<uint32_t>(vcpu, regs.rdx());
            // Windows has moved the userland stack pointer to RDX, move it back to make some room
            regs.rdx(regs.rdx() - stack_offset);
            break;
        case EventType::EVENT_FAST_SYSCALL_RET:
        case EventType::EVENT_EXCEPTION:
            // Set up a SYSENTER frame
            rip = regs.rip(); // Save the userland instruction pointer, SYSENTER will change it
            regs.rdx(regs.rsp() - stack_offset); // In Windows rdx holds the userland stack pointer
            break;
        default:
            // TODO: Handle breakpoint/HAP events
            LOG4CXX_WARN(syscall_injector_logger, "Invalid event type in begin_sysenter()");
            throw InvalidMethodException(); // TODO: Proper exception
        }

        rsp_ = regs.rdx();

        // Write the return address on our new stack
        *guest_ptr<uint32_t>(vcpu, regs.rdx()) = rip;

        // SECTEPE: this is the userland address SYSEXIT/SYSRET will return to;
        // the matching FAST_SYSCALL_RET for this injection lands here. Used to
        // disambiguate nested injections on the same thread in call().
        expected_return_rip_ = rip;
    }

    void begin_syscall(unsigned int arg_count, unsigned int additional_stack) {
        /*
         * Inject a SYSCALL.
         *
         * SYSCALL saves the return address for in RCX, no need to save it anywhere.
         * All we have to do is lower the stack pointer enough for our arguments.
         *
         * Local variables will be placed below the arguments.
         */
        auto& regs = event_.vcpu().registers();

        // Make sure we're aligned
        regs.rsp(regs.rsp() & ~0x7LL);

        const uint64_t stack_bottom = regs.rsp() - (arg_count + 2) * sizeof(uint64_t);

        // Prevents a recursive loop with NtDeleteFile to page in the stack
        if (arg_count > 4 || additional_stack > 0)
            verify_stack_present(stack_bottom - additional_stack, regs.rsp());

        // This works even if we're already in an EVENT_FAST_SYSCALL.
        // In KVM, since the RIP changes, it won't happen twice.
        // It will not work if the VCPU is already in the kernel, though!
        // For example, if we do this in a CR3 write event the guest will die.
        event_.vcpu().inject_syscall();

        // SECTEPE: SYSCALL stashes the userland return address (the instruction
        // after SYSCALL) in RCX, and the KVM layer reloads the registers after
        // injecting, so RCX is valid here. SYSRET restores RIP from RCX, so the
        // matching FAST_SYSCALL_RET for this injection returns to this address.
        // This is captured per-injector (each nested NtDeleteFile from
        // verify_stack_present is a distinct SystemCallInjector with its own
        // member) so returns are routed to the correct waiter in call().
        expected_return_rip_ = regs.rcx();

        regs.rsp(stack_bottom);

        rsp_ = regs.rsp();
    }

  private:
    std::optional<introvirt::inject::RegisterGuard> guard_;
    WindowsEvent& event_;
    WindowsGuest& guest_;
    std::optional<x86::Segment> original_cs_;
    uint64_t rsp_;

    // SECTEPE: userland return RIP for THIS injection's call site, used to
    // route the matching FAST_SYSCALL_RET to the correct waiter when nested
    // injections share a thread_id (see call()). Captured in
    // begin_syscall()/begin_sysenter() right after the SYSCALL/SYSENTER is
    // forced into the guest.
    std::optional<uint64_t> expected_return_rip_;
};

} // namespace inject
} // namespace windows
} // namespace introvirt