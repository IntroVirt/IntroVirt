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
#include <introvirt/core/memory/GuestVirtualAddress.hh>

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

    const GuestVirtualAddress pcurrent_thread(vcpu_.domain(), current_thread_address(), dtb);

    current_thread_ = kernel_.thread(pcurrent_thread);
    vcpu_.os_data(&current_thread_->Process());
}

template <typename PtrType>
KPCR_IMPL<PtrType>::KPCR_IMPL(NtKernelImpl<PtrType>& kernel, Vcpu& vcpu, uint64_t dtb)
    : kernel_(kernel), vcpu_(vcpu) {

    if (!dtb)
        dtb = vcpu.registers().cr3();

    // Load structure information
    offsets_ = LoadOffsets<structs::KPCR>(kernel_);

    const auto& registers = vcpu.registers();

    GuestVirtualAddress gva;

    // Find the address of the current KPCR
    if constexpr (std::is_same_v<uint64_t, PtrType>) {
        // Long-mode enabled, 64-bit mode
        // The GS base address should hold the KPCR
        // The kernel GS base will be in one of these two spots, depending on state
        gva = GuestVirtualAddress(vcpu_, std::max(registers.msr(x86::Msr::MSR_KERNEL_GS_BASE),
                                                  registers.msr(x86::Msr::MSR_GS_BASE)));
    } else {
        // In 32-bit mode, the KPCR is held in a GDT entry at offset 0x30
        const x86::Segment segment = vcpu.segment(KGDT_R0_PCR);
        gva = GuestVirtualAddress(vcpu, segment.base());
    }
    gva.page_directory(dtb);

    // Map in the KPCR structure
    buffer_.reset(gva, offsets_->size());

    // Create pointers for fast access
    pcurrent_thread_ = reinterpret_cast<PtrType*>(buffer_.get() + offsets_->Prcb.CurrentThread);
    pidle_thread_ = reinterpret_cast<PtrType*>(buffer_.get() + offsets_->Prcb.IdleThread);

    if (offsets_->Prcb.KernelDirectoryTableBase.exists()) {
        pkernel_dtb_ =
            reinterpret_cast<PtrType*>(buffer_.get() + offsets_->Prcb.KernelDirectoryTableBase);
    }

    // Validate it
    if (offsets_->Self.template get<PtrType>(buffer_) != gva.virtual_address()) {
        throw GuestDetectionException(vcpu, "Failed to validate 64-bit KPCR " + to_string(gva));
    }

    LOG4CXX_DEBUG(logger, "Detected Vcpu " << vcpu.id() << " KPCR at " << gva);
}

template <typename PtrType>
KPCR_IMPL<PtrType>::~KPCR_IMPL() = default;

template class KPCR_IMPL<uint32_t>;
template class KPCR_IMPL<uint64_t>;

} // namespace nt
} // namespace windows
} // namespace introvirt