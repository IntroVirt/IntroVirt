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
#include "KPCR_IMPL.hh"
#include "core/event/EventImpl.hh"
#include "windows/kernel/nt/NtKernelImpl.hh"

#include <introvirt/windows/exception/IdleThreadException.hh>
#include <introvirt/windows/kernel/nt/NtKernel.hh>
#include <introvirt/windows/kernel/nt/types/CLIENT_ID.hh>
#include <introvirt/windows/kernel/nt/types/HANDLE_TABLE.hh>
#include <introvirt/windows/kernel/nt/types/objects/PROCESS.hh>
#include <introvirt/windows/kernel/nt/types/objects/THREAD.hh>

#include <introvirt/core/arch/arch.hh>
#include <introvirt/core/domain/Vcpu.hh>
#include <introvirt/core/exception/GuestDetectionException.hh>
#include <introvirt/core/exception/TraceableException.hh>

#include <log4cxx/logger.h>

#include <algorithm>
#include <type_traits>

namespace introvirt {
namespace windows {
namespace nt {

static log4cxx::LoggerPtr
    logger(log4cxx::Logger::getLogger("introvirt.windows.kernel.nt.types.KPCR"));

// Used only in 32-bit Windows
static const x86::SegmentSelector KGDT_R0_PCR(0x30);

template <typename PtrType>
uint64_t KPCR_IMPL<PtrType>::pid() const {
    if (current_thread_ != nullptr)
        return CurrentThread().Cid().UniqueProcess();
    return 0;
}

template <typename PtrType>
uint64_t KPCR_IMPL<PtrType>::tid() const {
    if (current_thread_ != nullptr)
        return CurrentThread().Cid().UniqueThread();
    return 0;
}

template <typename PtrType>
std::string KPCR_IMPL<PtrType>::process_name() const {
    if (current_thread_ != nullptr)
        return CurrentThread().Process().ImageFileName();
    return "Idle";
}

template <typename PtrType>
THREAD& KPCR_IMPL<PtrType>::CurrentThread() {
    const auto* const_this = const_cast<const KPCR_IMPL<PtrType>*>(this);
    return const_cast<THREAD&>(const_this->CurrentThread());
}

template <typename PtrType>
const THREAD& KPCR_IMPL<PtrType>::CurrentThread() const {
    if (unlikely(current_thread_ == nullptr))
        throw IdleThreadException();
    return *current_thread_;
}

template <typename PtrType>
uint64_t KPCR_IMPL<PtrType>::KernelDirectoryTableBase() const {
    if (pkernel_dtb_ != nullptr)
        return *pkernel_dtb_;
    return 0;
}

template <typename PtrType>
bool KPCR_IMPL<PtrType>::idle() const {
    return *pcurrent_thread_ == *pidle_thread_;
}

template <typename PtrType>
uint64_t KPCR_IMPL<PtrType>::current_thread_address() const {
    return *pcurrent_thread_;
}

template <typename PtrType>
void KPCR_IMPL<PtrType>::reset() {
    /*
     * Shouldn't need locking.
     * There's only one KPCR per VCPU, so this should only ever be called by one VCPU at a time.
     */
    if (idle()) {
        current_thread_ = nullptr;
        return;
    }

    PtrType dtb = KernelDirectoryTableBase();
    if (!dtb)
        dtb = vcpu_.registers().cr3();

    /*
     * Building the current THREAD here can fail when this VCPU is observed mid-context-switch, or is
     * in user mode under KPTI with no KernelDirectoryTableBase available (so dtb falls back to the
     * user CR3 above). In those cases current_thread_address() resolves through the wrong page
     * tables and yields a garbage/non-canonical pointer, and the subsequent THREAD/OBJECT_HEADER
     * read throws (e.g. IncorrectTypeException "Type index out of range", or
     * VirtualAddressNotPresentException for a non-canonical VA).
     *
     * This reset() runs on the VCPU poller thread while building an event (via
     * WindowsEventTaskInformation -> WindowsEventImpl), where the surrounding loop only catches
     * EventPollException -- so any throw here would escape and std::terminate the process. This is
     * easy to trigger while another VCPU is performing syscall injection (NtCreateUserProcess),
     * which churns context switches on the other VCPUs.
     *
     * Prevent the bad read at the source: KPRCB.CurrentThread always holds a canonical kernel-half
     * pointer (>= 0xFFFF800000000000) for any real thread. A value outside that range is a torn /
     * stale read (e.g. the non-canonical 0x8A.. variant, or a user-half value seen mid-switch), so
     * reject it up front -- this is cheaper and safer than walking the page tables and constructing
     * a THREAD/OBJECT_HEADER only to throw deep inside. PageDirectory::translate() masks the top 16
     * bits off the VA (va_mask_), so a non-canonical pointer would otherwise silently alias a
     * present-but-wrong page and mis-decode an object header rather than failing cleanly.
     *
     * Either way (rejected here, or a residual canonical-but-stale pointer that still throws in the
     * try below) we degrade to the idle() case above: current_thread_ == nullptr is already a
     * legitimate, supported state. Downstream KPCR_IMPL::pid()/tid()/process_name() are already
     * null-safe; the only callers that throw on a null current thread (KPCR::CurrentThread() ->
     * IdleThreadException) run later in the event_deliverer / callback path, which catches
     * TraceableException per-event. We clear os_data as well so the stale PROCESS pointer from a
     * previous event is not reused; all os_data consumers already null-check it.
     */
    if constexpr (std::is_same_v<uint64_t, PtrType>) {
        // x86_64 canonical kernel half. 32-bit kernels use the whole 4 GiB range for kernel
        // pointers, so this guard only applies to long mode.
        static constexpr uint64_t kKernelHalf = 0xFFFF800000000000ULL;
        if (unlikely(current_thread_address() < kKernelHalf)) {
            LOG4CXX_DEBUG(logger, "Vcpu " << vcpu_.id()
                                          << " current thread pointer not in kernel half ("
                                          << n2hexstr(current_thread_address())
                                          << "), treating as no current thread");
            current_thread_ = nullptr;
            vcpu_.os_data(nullptr);
            return;
        }
    }

    /*
     * Count consecutive residual read failures so a genuine, non-transient
     * regression in THREAD/object parsing stays visible (the FIRST failure of a
     * streak is logged at WARN, even when DEBUG is disabled), while a stuck vcpu
     * does not spam a WARN per event. reset() is only ever called from the
     * event-construction path on a vcpu's own poller thread, so this thread_local
     * counter is effectively per-vcpu and needs no synchronization. It is reset to
     * zero whenever the current thread reads cleanly.
     */
    thread_local uint64_t reset_failures = 0;

    try {
        const guest_ptr<void> pcurrent_thread(vcpu_.domain(), current_thread_address(), dtb);

        current_thread_ = kernel_.thread(pcurrent_thread);
        vcpu_.os_data(&current_thread_->Process());

        // Clean read: clear any failure streak so the next bad read is logged
        // loudly again.
        reset_failures = 0;
    } catch (const TraceableException& ex) {
        /*
         * Residual canonical-but-stale pointer that still failed to parse a
         * THREAD/OBJECT_HEADER. Degrade to the idle() state (current_thread_ ==
         * nullptr) and clear os_data so the previous event's PROCESS pointer is
         * not reused.
         */
        if (unlikely(reset_failures++ % 1000 == 0)) {
            LOG4CXX_WARN(logger, "Vcpu " << vcpu_.id()
                                         << " failed to read current thread during KPCR reset "
                                            "(failure #"
                                         << reset_failures
                                         << "), treating as no current thread: " << ex.what());
        } else {
            LOG4CXX_DEBUG(logger, "Vcpu " << vcpu_.id()
                                          << " failed to read current thread during KPCR reset, "
                                             "treating as no current thread: "
                                          << ex.what());
        }
        current_thread_ = nullptr;
        vcpu_.os_data(nullptr);
    }
}

template <typename PtrType>
KPCR_IMPL<PtrType>::KPCR_IMPL(NtKernelImpl<PtrType>& kernel, Vcpu& vcpu, uint64_t dtb)
    : kernel_(kernel), vcpu_(vcpu) {

    if (!dtb)
        dtb = vcpu.registers().cr3();

    // Load structure information
    offsets_ = LoadOffsets<structs::KPCR>(kernel_);

    const Domain& domain = vcpu.domain();
    const auto& registers = vcpu.registers();

    // Find the address of the current KPCR and map it in
    if constexpr (std::is_same_v<uint64_t, PtrType>) {
        // Long-mode enabled, 64-bit mode
        // The GS base address should hold the KPCR
        // The kernel GS base will be in one of these two spots, depending on state
        buffer_.reset(domain,
                      std::max(registers.msr(x86::Msr::MSR_KERNEL_GS_BASE),
                               registers.msr(x86::Msr::MSR_GS_BASE)),
                      dtb, offsets_->size());
    } else {
        // In 32-bit mode, the KPCR is held in a GDT entry at offset 0x30
        const x86::Segment segment = vcpu.segment(KGDT_R0_PCR);
        buffer_.reset(domain, segment.base(), dtb, offsets_->size());
    }

    // Create pointers for fast access
    pcurrent_thread_ = reinterpret_cast<PtrType*>(buffer_.get() + offsets_->Prcb.CurrentThread);
    pidle_thread_ = reinterpret_cast<PtrType*>(buffer_.get() + offsets_->Prcb.IdleThread);

    if (offsets_->Prcb.KernelDirectoryTableBase.exists()) {
        pkernel_dtb_ =
            reinterpret_cast<PtrType*>(buffer_.get() + offsets_->Prcb.KernelDirectoryTableBase);
    }

    // Validate it
    if (unlikely(offsets_->Self.template get<PtrType>(buffer_) != buffer_.address())) {
        throw GuestDetectionException(vcpu, "Failed to validate 64-bit KPCR " +
                                                n2hexstr(buffer_.address()));
    }

    LOG4CXX_DEBUG(logger,
                  "Detected Vcpu " << vcpu.id() << " KPCR at " << n2hexstr(buffer_.address()));
}

template <typename PtrType>
KPCR_IMPL<PtrType>::~KPCR_IMPL() = default;

template class KPCR_IMPL<uint32_t>;
template class KPCR_IMPL<uint64_t>;

} // namespace nt
} // namespace windows
} // namespace introvirt