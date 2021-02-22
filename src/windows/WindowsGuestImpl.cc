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
#include "WindowsGuestImpl.hh"
#include "common/TypeOffsets.hh"
#include "kernel/nt/structs/structs.hh"
#include "windows/event/WindowsEventImpl.hh"
#include "windows/event/WindowsSystemCallEventImpl.hh"
#include "windows/kernel/nt/structs/structs.hh"
#include <introvirt/core/event/ThreadLocalEvent.hh>

#include <introvirt/core/core.hh>
#include <introvirt/util/compiler.hh>
#include <introvirt/windows/WindowsGuest.hh>
#include <introvirt/windows/kernel/nt/NtKernel.hh>
#include <introvirt/windows/kernel/nt/syscall/NtAllocateVirtualMemory.hh>
#include <introvirt/windows/kernel/nt/syscall/NtClose.hh>
#include <introvirt/windows/kernel/nt/syscall/NtFreeVirtualMemory.hh>
#include <introvirt/windows/kernel/nt/syscall/NtOpenProcess.hh>
#include <introvirt/windows/kernel/nt/syscall/NtReadVirtualMemory.hh>
#include <introvirt/windows/kernel/nt/types/KPCR.hh>
#include <introvirt/windows/kernel/nt/types/MMVAD.hh>
#include <introvirt/windows/kernel/nt/types/objects/PROCESS.hh>
#include <introvirt/windows/kernel/nt/types/objects/THREAD.hh>
#include <introvirt/windows/kernel/nt/util/util.hh>

#include <log4cxx/logger.h>

#include <algorithm>
#include <array>
#include <mutex>

namespace introvirt {
namespace windows {

static log4cxx::LoggerPtr logger(log4cxx::Logger::getLogger("introvirt.windows.WindowsGuest"));

extern std::set<SystemCallIndex> supported_syscalls_set;
extern std::set<std::string> syscall_categories_set;
extern std::multimap<std::string, SystemCallIndex> syscall_categories_map;

template <typename PtrType>
void WindowsGuestImpl<PtrType>::default_syscall_filter(SystemCallFilter& filter) const {
    for (auto& entry : supported_syscalls_set) {
        set_system_call_filter(filter, entry, true);
    }
}

std::set<std::string> WindowsGuest::syscall_categories() { return syscall_categories_set; }

template <typename PtrType>
void WindowsGuestImpl<PtrType>::enable_category(const std::string& category,
                                                SystemCallFilter& filter) const {

    auto results = syscall_categories_map.equal_range(category);
    for (auto iter = results.first; iter != results.second; ++iter) {
        set_system_call_filter(filter, iter->second, true);
    }
}

template <typename PtrType>
std::unique_ptr<Event>
WindowsGuestImpl<PtrType>::filter_event(std::unique_ptr<HypervisorEvent>&& hypervisor_event) {
    // Just deliver these as-is without adding OS stuff.
    return std::make_unique<WindowsEventImpl>(*this, std::move(hypervisor_event));
}

template <typename PtrType>
template <typename PteType>
GuestPageFaultResult WindowsGuestImpl<PtrType>::handle_prototype_pte(const GuestVirtualAddress& gva,
                                                                     PteType& pte) const {
    LOG4CXX_DEBUG(logger, "Following prototype PTE at " << gva);
    char* buffer = reinterpret_cast<char*>(&pte);

    constexpr int MM_DECOMMIT = 0x10;

    try {
        // Read the PTE
        pte = *guest_ptr<PteType>(gva);
    } catch (TraceableException& ex) {
        LOG4CXX_WARN(logger, "Failed to read prototype PTE at " << gva);
        return GuestPageFaultResult::FAILURE;
    }

    // Read some fields
    bool valid = mmpte_hardware_->Valid.get_bitfield<PteType>(buffer);
    if (valid) {
        LOG4CXX_DEBUG(logger, "Prototype PTE is valid: 0x" << std::hex << pte);
        return GuestPageFaultResult::PTE_FIXED;
    }

    const bool prototype = mmpte_transition_->Prototype.get_bitfield<PteType>(buffer);
    const bool transition = mmpte_transition_->Transition.get_bitfield<PteType>(buffer);

    if (transition || prototype) {
        // If the SwizzleBit is NOT set, we have to bit-flip against PteInvalidMask (if set)
        const bool SwizzleBit = !mmpte_prototype_->SwizzleBit.exists() ||
                                mmpte_prototype_->SwizzleBit.get_bitfield<PteType>(buffer);

        if (kernel().InvalidPteMask() && !SwizzleBit) {
            pte = pte & ~(kernel().InvalidPteMask());
        }
    }

    if (!prototype) {
        if (transition) {
            uint8_t protection = mmpte_transition_->Protection.get_bitfield<uint8_t>(buffer);
            if (protection & MM_DECOMMIT) {
                LOG4CXX_WARN(
                    logger,
                    "Transition PTE has MM_DECOMMIT set: PFN=0x"
                        << std::hex
                        << mmpte_transition_->PageFrameNumber.get_bitfield<uint64_t>(buffer));
                return GuestPageFaultResult::FAILURE;
            }

            // The PTE is basically valid, we just have to set the valid bit.
            mmpte_hardware_->Valid.set_bitfield<PteType>(buffer, 1);
            LOG4CXX_DEBUG(logger, "Prototype PTE made valid: 0x" << std::hex << pte);
            return GuestPageFaultResult::PTE_FIXED;
        } else {
            // Page is really paged out to swap file.
        }
    } else {
        // TODO: Handle _SUBSECTION object
    }

    return GuestPageFaultResult::FAILURE;
}

template <typename PtrType>
template <typename PteType>
GuestPageFaultResult
WindowsGuestImpl<PtrType>::handle_page_fault_mmvad(const GuestVirtualAddress& gva,
                                                   PteType& pte) const {

    // TODO: We really want the region of memory that the kernel address space starts at.
    // The kernel image isn't necessarly the start of the kernel memory region
    if (gva > kernel().base_address()) {
        return GuestPageFaultResult::FAILURE;
    }

    // TODO: This all feels hacky
    auto& event = ThreadLocalEvent::get();
    const Vcpu& vcpu = event.vcpu();
    const auto* process = reinterpret_cast<const nt::PROCESS*>(vcpu.os_data());
    if (!process) {
        return GuestPageFaultResult::FAILURE;
    }

    auto vadroot = process->VadRoot();
    if (!vadroot) {
        return GuestPageFaultResult::FAILURE;
    }

    // Get the VaD entry for the address in question
    auto vad = vadroot->search(gva);
    if (!vad) {
        return GuestPageFaultResult::FAILURE;
    }

    // Get the first PTE for this region
    auto FirstPrototypePte = vad->FirstPrototypePte();
    if (!FirstPrototypePte) {
        // I believe this means the page will be created and zeroed on access.
        return GuestPageFaultResult::FAILURE;
    }

    // Offset into the region's PTEs
    const uint64_t index = (gva - vad->StartingAddress()) >> PageDirectory::PAGE_SHIFT;
    const GuestVirtualAddress ProtoAddress = FirstPrototypePte + (sizeof(PteType) * index);
    if (ProtoAddress > vad->LastContiguousPte()) {
        // No PTE for this page
        return GuestPageFaultResult::FAILURE;
    }

    return handle_prototype_pte<PteType>(ProtoAddress, pte);
}

template <typename PtrType>
template <typename PteType>
GuestPageFaultResult
WindowsGuestImpl<PtrType>::handle_page_fault_internal(const GuestVirtualAddress& gva,
                                                      PteType& pte) const {

    // If we're here, the main page directory code hit a not-present page.
    // See if we can fix that, here.

    LOG4CXX_TRACE(logger,
                  "Handling Windows PTE fault for " << gva << " Value : 0x" << std::hex << pte);

    char* buffer = reinterpret_cast<char*>(&pte);
    const bool prototype = mmpte_transition_->Prototype.get_bitfield<PteType>(buffer);
    const bool transition = mmpte_transition_->Transition.get_bitfield<PteType>(buffer);

    GuestPageFaultResult result;

    if (transition || prototype) {
        // If the SwizzleBit is NOT set, we have to bit-flip against PteInvalidMask (if set)
        const bool SwizzleBit = !mmpte_prototype_->SwizzleBit.exists() ||
                                mmpte_prototype_->SwizzleBit.get_bitfield<PteType>(buffer);
        if (kernel().InvalidPteMask() && !SwizzleBit) {
            pte = pte & ~(kernel().InvalidPteMask());
        }
    }

    if (!prototype) {
        if (transition) {
            /*
             * If the PTE is not a prototype, and it is in transition, we can just treat it as a
             * valid PTE. This means we can just return the PTE with the valid bit set.
             */
            mmpte_hardware_->Valid.set_bitfield<PteType>(buffer, 1);
            LOG4CXX_DEBUG(logger, "Fixed transition PTE");
            return GuestPageFaultResult::PTE_FIXED;
        } else {
            /*
             * Not valid, not prototype, not transition.
             * If the PageFileHigh bit is set, then it's really paged out.
             * Otherwise, consult the VAD.
             */
            if (mmpte_software_->PageFileHigh.get_bitfield<PteType>(buffer) == 0) {
                // Should be demand-zero paging
                // return handle_page_fault_mmvad<PteType>(gva);
                result = GuestPageFaultResult::FAILURE;
            } else {
                // Page is really paged out to swap file
                result = GuestPageFaultResult::FAILURE;
            }
        }
    } else {
        /*
         * A Prototype PTE is basically a symlink. Windows does this for shared memory.
         */
        // Get the pointer to the actual PTE and map it in
        uint64_t ProtoAddress = mmpte_prototype_->ProtoAddress.get_bitfield<PteType>(buffer);

        // The 0xFFFFFFFF0000 mask is a special indicator for Vad Lookup
        if ((ProtoAddress & 0xFFFFFFFF0000) != 0xFFFFFFFF0000) {
            if constexpr (is64Bit()) {
                ProtoAddress |= 0xFFFF000000000000;
            }
            result = handle_prototype_pte<PteType>(gva.create(ProtoAddress), pte);
        } else {
            // VaD lookup required
            result = handle_page_fault_mmvad<PteType>(gva, pte);
        }
    }

    if (result != GuestPageFaultResult::FAILURE)
        return result; // We handled it

    // Try to perform injection
    try {
#if 0
        const auto& event = static_cast<WindowsEvent&>(Event::thread_local_event());

        switch (event.type()) {
        case EventType::EVENT_FAST_SYSCALL:
        case EventType::EVENT_FAST_SYSCALL_RET:
            break;
        default:
            return GuestPageFaultResult::FAILURE;
        }

        LOG4CXX_WARN(logger, "Trying syscall injection for paged out memory!!");

        // We store the PROCESS object in the VCPU's os_data()
        const Vcpu& vcpu = gva.vcpu();
        const auto* process = reinterpret_cast<const nt::PROCESS*>(vcpu.os_data());
        if (!process) {
            LOG4CXX_WARN(logger, "Process is nullptr");
            return GuestPageFaultResult::FAILURE;
        }

        using namespace windows::nt;


        uint64_t process_handle = 0;
        if (event.task().pid() == process->UniqueProcessId()) {
            // We are already in the right process
            process_handle = NtCurrentProcess();
            LOG4CXX_WARN(logger, "Using self handle");
        } else {
            LOG4CXX_WARN(logger, "Opening target process");
            // We have to try opening the target process
            auto object_attributes = inject::allocate<nt::OBJECT_ATTRIBUTES>();
            auto client_id = inject::allocate<nt::CLIENT_ID>(process->UniqueProcessId(), 0);
            const uint32_t access_mask = ACCESS_MASK::PROCESS_VM_READ |
                                         ACCESS_MASK::PROCESS_VM_OPERATION |
                                         ACCESS_MASK::PROCESS_QUERY_INFORMATION;
            auto syscall_result = inject::system_call<nt::NtOpenProcess>(
                process_handle, access_mask, object_attributes, client_id);

            if (!syscall_result.NT_SUCCESS()) {
                LOG4CXX_WARN(logger,
                             "Failed to call NtOpenProcess for page in: " << syscall_result);
                return GuestPageFaultResult::FAILURE;
            }
        }

        auto temp_buffer = inject::allocate<uint8_t>();

        auto syscall_result =
            inject::system_call<NtReadVirtualMemory>(process_handle, gva, temp_buffer, 1, nullptr);

        if (!syscall_result.NT_SUCCESS()) {
            LOG4CXX_WARN(logger,
                         "Failed to call NtReadVirtualMemory for page in: " << syscall_result);
            result = GuestPageFaultResult::FAILURE;
        } else {
            LOG4CXX_WARN(logger, "Successfully paged in " << gva);
            result = GuestPageFaultResult::RETRY;
        }

        if (process_handle != NtCurrentProcess())
            inject::system_call<nt::NtClose>(process_handle);

#endif
        return result;

    } catch (InvalidMethodException& ex) {
        // TODO: Update InvalidMethodException when we have a better exception class.
        return GuestPageFaultResult::FAILURE;
    }
}

thread_local unsigned int PageFaultDepth = 0;

template <typename PtrType>
GuestPageFaultResult WindowsGuestImpl<PtrType>::handle_page_fault(const GuestVirtualAddress& gva,
                                                                  uint64_t& pte) const {

    if (unlikely(!ThreadLocalEvent::active()))
        return GuestPageFaultResult::FAILURE;

    if (unlikely(PageFaultDepth > 50)) {
        LOG4CXX_WARN(logger, "Max depth exceeded for handle_page_fault. Faulting address: " << gva);
        return GuestPageFaultResult::FAILURE;
    }

    ++PageFaultDepth;

    try {
        GuestPageFaultResult result;
        if (mmpte_transition_->size() == 8) {
            result = handle_page_fault_internal<uint64_t>(gva, pte);
        } else {
            uint32_t pte32 = pte;
            result = handle_page_fault_internal<uint32_t>(gva, pte32);
            pte = pte32;
        }

        --PageFaultDepth;
        return result;
    } catch (...) {
        --PageFaultDepth;
        throw;
    }
}

template <typename PtrType>
bool WindowsGuestImpl<PtrType>::set_system_call_filter(SystemCallFilter& filter,
                                                       SystemCallIndex index, bool value) const {
    // Get the native value for the given system call index
    const uint32_t native_call_idx = syscalls().native(index);
    if (unlikely(native_call_idx == 0xFFFFFFFF))
        return false;

    if constexpr (is64Bit()) {
        filter.set_64(native_call_idx, value);
    } else {
        filter.set_32(native_call_idx, value);
    }

    return true;
}

template <typename PtrType>
bool WindowsGuestImpl<PtrType>::x64() const {
    return is64Bit();
}

template <typename PtrType>
OS WindowsGuestImpl<PtrType>::os() const {
    return OS::Windows;
}

template <typename PtrType>
const SystemCallConverter& WindowsGuestImpl<PtrType>::syscalls() const {
    return *syscalls_;
}

template <typename PtrType>
nt::NtKernel& WindowsGuestImpl<PtrType>::kernel() {
    return *kernel_;
}

template <typename PtrType>
const nt::NtKernel& WindowsGuestImpl<PtrType>::kernel() const {
    return *kernel_;
}

template <typename PtrType>
Domain& WindowsGuestImpl<PtrType>::domain() {
    return *domain_;
}

template <typename PtrType>
const Domain& WindowsGuestImpl<PtrType>::domain() const {
    return *domain_;
}

template <typename PtrType>
GuestVirtualAddress WindowsGuestImpl<PtrType>::allocate(size_t& RegionSize, bool executable) {
    auto& event = static_cast<WindowsEvent&>(ThreadLocalEvent::get());

    const nt::PAGE_PROTECTION prot = (executable) ? nt::PAGE_PROTECTION::PAGE_EXECUTE_READWRITE
                                                  : nt::PAGE_PROTECTION::PAGE_READWRITE;

    size_t BaseAddress = 0;
    size_t ZeroBits = 0;

    // If the process is a WoW64 process, we want memory in the 32-bit range
    if (event.task().pcr().CurrentThread().Process().isWow64Process()) {
        ZeroBits = 0x7FFFFFFFF;
    }

    nt::NTSTATUS result = inject::system_call<nt::NtAllocateVirtualMemory>(
        0xFFFFFFFFFFFFFFFFLL, BaseAddress, ZeroBits, RegionSize, nt::MEM_COMMIT | nt::MEM_RESERVE,
        prot);

    if (unlikely(!result.NT_SUCCESS())) {
        // TODO: Throw an exception
        LOG4CXX_WARN(logger, "Allocation call to NtAllocateVirtualMemory failed: " << result);
        return GuestVirtualAddress();
    }

    GuestVirtualAddress gva(event.vcpu(), BaseAddress);

    // Page the region in
    // TODO: Should probably NtLockVirtualMemory instead

    const auto end_addr = gva + RegionSize;
    for (auto addr = gva; addr < end_addr; addr += x86::PageDirectory::PAGE_SIZE) {
        result = inject::system_call<nt::NtReadVirtualMemory>(0xFFFFFFFFFFFFFFFFLL, addr, addr, 1,
                                                              nullptr);
        if (unlikely(!result.NT_SUCCESS())) {
            // TODO: Throw an exception
            LOG4CXX_WARN(logger, "Page-in call to NtReadVirtualMemory failed: " << result);
            return GuestVirtualAddress();
        }
    }

    return gva;
}

template <typename PtrType>
void WindowsGuestImpl<PtrType>::guest_free(GuestVirtualAddress& BaseAddress, size_t RegionSize) {
    try {
        nt::NTSTATUS result = inject::system_call<nt::NtFreeVirtualMemory>(
            nt::NtCurrentProcess(), BaseAddress.value(), RegionSize, nt::MEM_RELEASE);

        if (unlikely(!result.NT_SUCCESS())) {
            LOG4CXX_WARN(logger, "Free call to NtFreeVirtualMemory failed: " << result);
            return;
        }

    } catch (TraceableException& ex) {
        LOG4CXX_WARN(logger, "Failed to free guest memory due to exception: " << ex);
    }
}

template <typename PtrType>
WindowsGuestImpl<PtrType>::WindowsGuestImpl(Domain& domain) : domain_(&domain) {
    domain.pause();

    try {
        // Bootstrap the kernel
        kernel_.emplace(*this);

        mmpte_hardware_ = LoadOffsets<nt::structs::MMPTE_HARDWARE>(*kernel_);
        mmpte_prototype_ = LoadOffsets<nt::structs::MMPTE_PROTOTYPE>(*kernel_);
        mmpte_software_ = LoadOffsets<nt::structs::MMPTE_SOFTWARE>(*kernel_);
        mmpte_transition_ = LoadOffsets<nt::structs::MMPTE_TRANSITION>(*kernel_);

        // Prepare the system call numbers
        syscalls_.emplace(*this);

    } catch (TraceableException& ex) {
        // Only a debug message because this occasionally fails
        // DomainImpl::detect_os() will try a few times, though.
        LOG4CXX_DEBUG(logger, ex);
        domain.resume();
        throw GuestDetectionException(domain, ex.what());
    }

    // Configure the system call bitmaps with our mask
    domain.system_call_filter().mask(SystemCallConverter::SystemCallIndexMask);
    for (uint32_t id = domain.vcpu_count(); id < domain.vcpu_count(); ++id) {
        Vcpu& vcpu = domain.vcpu(id);
        vcpu.system_call_filter().mask(SystemCallConverter::SystemCallIndexMask);
    }

    domain.resume();
}

template class WindowsGuestImpl<uint32_t>;
template class WindowsGuestImpl<uint64_t>;

} // namespace windows
} // namespace introvirt
