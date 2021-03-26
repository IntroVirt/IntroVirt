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
#include "PROCESS_INFORMATION_IMPL.hh"
#include <introvirt/core/event/ThreadLocalEvent.hh>

#include <introvirt/core/domain/Vcpu.hh>
#include <introvirt/windows/WindowsGuest.hh>
#include <introvirt/windows/event/WindowsEvent.hh>
#include <introvirt/windows/kernel/nt/types/KPCR.hh>
#include <introvirt/windows/kernel/nt/types/objects/PROCESS.hh>
#include <introvirt/windows/kernel/nt/types/objects/THREAD.hh>

#include <cassert>
#include <cstring>

namespace introvirt {
namespace windows {
namespace kernel32 {

template <typename PtrType>
uint64_t PROCESS_INFORMATION_IMPL<PtrType>::hProcess() const {
    return ptr_->hProcess;
}
template <typename PtrType>
void PROCESS_INFORMATION_IMPL<PtrType>::hProcess(uint64_t hProcess) {
    ptr_->hProcess = hProcess;
}

template <typename PtrType>
uint64_t PROCESS_INFORMATION_IMPL<PtrType>::hThread() const {
    return ptr_->hThread;
}
template <typename PtrType>
void PROCESS_INFORMATION_IMPL<PtrType>::hThread(uint64_t hThread) {
    ptr_->hThread = hThread;
}

template <typename PtrType>
uint32_t PROCESS_INFORMATION_IMPL<PtrType>::dwProcessId() const {
    return ptr_->dwProcessId;
}
template <typename PtrType>
void PROCESS_INFORMATION_IMPL<PtrType>::dwProcessId(uint32_t dwProcessId) {
    ptr_->dwProcessId = dwProcessId;
}

template <typename PtrType>
uint32_t PROCESS_INFORMATION_IMPL<PtrType>::dwThreadId() const {
    return ptr_->dwThreadId;
}
template <typename PtrType>
void PROCESS_INFORMATION_IMPL<PtrType>::dwThreadId(uint32_t dwThreadId) {
    ptr_->dwThreadId = dwThreadId;
}

template <typename PtrType>
guest_ptr<void> PROCESS_INFORMATION_IMPL<PtrType>::address() const {
    return ptr_;
}

template <typename PtrType>
PROCESS_INFORMATION_IMPL<PtrType>::PROCESS_INFORMATION_IMPL(const guest_ptr<void>& ptr)
    : ptr_(ptr) {}

std::shared_ptr<PROCESS_INFORMATION> PROCESS_INFORMATION::make_shared(const guest_ptr<void>& ptr,
                                                                      bool x64) {
    if (x64) {
        return std::make_shared<PROCESS_INFORMATION_IMPL<uint64_t>>(ptr);
    } else {
        return std::make_shared<PROCESS_INFORMATION_IMPL<uint32_t>>(ptr);
    }
}

} // namespace kernel32
} // namespace windows

namespace inject {

GuestAllocation<windows::kernel32::PROCESS_INFORMATION>::GuestAllocation() {
    using namespace windows;
    using namespace windows::kernel32;

    auto& domain = Domain::thread_local_domain();
    auto* guest = static_cast<windows::WindowsGuest*>(domain.guest());
    introvirt_assert(guest != nullptr, "");

    bool x64 = (guest->x64());

    if (x64) {
        // Check for WoW64
        auto& event = static_cast<WindowsEvent&>(ThreadLocalEvent::get());
        if (event.task().pcr().CurrentThread().Process().isWow64Process()) {
            // We can assume the caller is executing CreateProcessA and will need a 32-bit version.
            x64 = false;
        }
    }

    // Get the size required for the structure
    const size_t structure_size = (x64) ? sizeof(structs::_PROCESS_INFORMATION<uint64_t>)
                                        : sizeof(structs::_PROCESS_INFORMATION<uint32_t>);

    // Allocate memory for the size of the structure plus the size of the string
    allocation_.emplace(structure_size);
    auto& ptr = allocation_->ptr();

    // Zero it
    memset(ptr.get(), 0, structure_size);

    // Create the structure
    value_ = PROCESS_INFORMATION::make_shared(ptr, x64);
}

} // namespace inject
} // namespace introvirt