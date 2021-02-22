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
#include "STARTUPINFO_IMPL.hh"
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
uint32_t STARTUPINFO_IMPL<PtrType>::cb() const {
    return buffer_->cb;
}
template <typename PtrType>
void STARTUPINFO_IMPL<PtrType>::cb(uint32_t cb) {
    buffer_->cb = cb;
}

template <typename PtrType>
GuestVirtualAddress STARTUPINFO_IMPL<PtrType>::lpReserved() const {
    return gva_.create(buffer_->lpReserved);
}
template <typename PtrType>
void STARTUPINFO_IMPL<PtrType>::lpReserved(const GuestVirtualAddress& lpReserved) {
    buffer_->lpReserved = lpReserved.value();
}

template <typename PtrType>
GuestVirtualAddress STARTUPINFO_IMPL<PtrType>::lpDesktop() const {
    return gva_.create(buffer_->lpDesktop);
}
template <typename PtrType>
void STARTUPINFO_IMPL<PtrType>::lpDesktop(const GuestVirtualAddress& lpDesktop) {
    buffer_->lpDesktop = lpDesktop.value();
}

template <typename PtrType>
GuestVirtualAddress STARTUPINFO_IMPL<PtrType>::lpTitle() const {
    return gva_.create(buffer_->lpTitle);
}
template <typename PtrType>
void STARTUPINFO_IMPL<PtrType>::lpTitle(const GuestVirtualAddress& lpTitle) {
    buffer_->lpTitle = lpTitle.value();
}

template <typename PtrType>
uint32_t STARTUPINFO_IMPL<PtrType>::dwX() const {
    return buffer_->dwX;
}
template <typename PtrType>
void STARTUPINFO_IMPL<PtrType>::dwX(uint32_t dwX) {
    buffer_->dwX = dwX;
}

template <typename PtrType>
uint32_t STARTUPINFO_IMPL<PtrType>::dwY() const {
    return buffer_->dwY;
}
template <typename PtrType>
void STARTUPINFO_IMPL<PtrType>::dwY(uint32_t dwY) {
    buffer_->dwY = dwY;
}

template <typename PtrType>
uint32_t STARTUPINFO_IMPL<PtrType>::dwXSize() const {
    return buffer_->dwXSize;
}
template <typename PtrType>
void STARTUPINFO_IMPL<PtrType>::dwXSize(uint32_t dwXSize) {
    buffer_->dwXSize = dwXSize;
}

template <typename PtrType>
uint32_t STARTUPINFO_IMPL<PtrType>::dwYSize() const {
    return buffer_->dwYSize;
}
template <typename PtrType>
void STARTUPINFO_IMPL<PtrType>::dwYSize(uint32_t dwYSize) {
    buffer_->dwYSize = dwYSize;
}

template <typename PtrType>
uint32_t STARTUPINFO_IMPL<PtrType>::dwXCountChars() const {
    return buffer_->dwXCountChars;
}
template <typename PtrType>
void STARTUPINFO_IMPL<PtrType>::dwXCountChars(uint32_t dwXCountChars) {
    buffer_->dwXCountChars = dwXCountChars;
}

template <typename PtrType>
uint32_t STARTUPINFO_IMPL<PtrType>::dwYCountChars() const {
    return buffer_->dwYCountChars;
}
template <typename PtrType>
void STARTUPINFO_IMPL<PtrType>::dwYCountChars(uint32_t dwYCountChars) {
    buffer_->dwYCountChars = dwYCountChars;
}

template <typename PtrType>
uint32_t STARTUPINFO_IMPL<PtrType>::dwFillAttribute() const {
    return buffer_->dwFillAttribute;
}
template <typename PtrType>
void STARTUPINFO_IMPL<PtrType>::dwFillAttribute(uint32_t dwFillAttribute) {
    buffer_->dwFillAttribute = dwFillAttribute;
}

template <typename PtrType>
uint32_t STARTUPINFO_IMPL<PtrType>::dwFlags() const {
    return buffer_->dwFlags;
}
template <typename PtrType>
void STARTUPINFO_IMPL<PtrType>::dwFlags(uint32_t dwFlags) {
    buffer_->dwFlags = dwFlags;
}

template <typename PtrType>
int32_t STARTUPINFO_IMPL<PtrType>::wShowWindow() const {
    return buffer_->wShowWindow;
}
template <typename PtrType>
void STARTUPINFO_IMPL<PtrType>::wShowWindow(int32_t wShowWindow) {
    buffer_->wShowWindow = wShowWindow;
}

template <typename PtrType>
int32_t STARTUPINFO_IMPL<PtrType>::cbReserved2() const {
    return buffer_->cbReserved2;
}
template <typename PtrType>
void STARTUPINFO_IMPL<PtrType>::cbReserved2(int32_t cbReserved2) {
    buffer_->cbReserved2 = cbReserved2;
}

template <typename PtrType>
GuestVirtualAddress STARTUPINFO_IMPL<PtrType>::lpReserved2() const {
    return gva_.create(buffer_->lpReserved2);
}
template <typename PtrType>
void STARTUPINFO_IMPL<PtrType>::lpReserved2(const GuestVirtualAddress& lpReserved2) {
    buffer_->lpReserved2 = lpReserved2.value();
}

template <typename PtrType>
uint64_t STARTUPINFO_IMPL<PtrType>::hStdInput() const {
    return buffer_->hStdInput;
}
template <typename PtrType>
void STARTUPINFO_IMPL<PtrType>::hStdInput(uint64_t hStdInput) {
    buffer_->hStdInput = hStdInput;
}

template <typename PtrType>
uint64_t STARTUPINFO_IMPL<PtrType>::hStdOutput() const {
    return buffer_->hStdOutput;
}
template <typename PtrType>
void STARTUPINFO_IMPL<PtrType>::hStdOutput(uint64_t hStdOutput) {
    buffer_->hStdOutput = hStdOutput;
}

template <typename PtrType>
uint64_t STARTUPINFO_IMPL<PtrType>::hStdError() const {
    return buffer_->hStdError;
}
template <typename PtrType>
void STARTUPINFO_IMPL<PtrType>::hStdError(uint64_t hStdError) {
    buffer_->hStdError = hStdError;
}

template <typename PtrType>
GuestVirtualAddress STARTUPINFO_IMPL<PtrType>::address() const {
    return gva_;
}

template <typename PtrType>
STARTUPINFO_IMPL<PtrType>::STARTUPINFO_IMPL(const GuestVirtualAddress& gva)
    : gva_(gva), buffer_(gva_) {}

std::unique_ptr<STARTUPINFO> STARTUPINFO::make_unique(const GuestVirtualAddress& gva) {
    auto& event = ThreadLocalEvent::get();
    auto& vcpu = event.vcpu();

    if (vcpu.long_mode() && !vcpu.long_compatibility_mode()) {
        return std::make_unique<STARTUPINFO_IMPL<uint64_t>>(gva);
    } else {
        return std::make_unique<STARTUPINFO_IMPL<uint32_t>>(gva);
    }
}

} // namespace kernel32
} // namespace windows

namespace inject {

GuestAllocation<windows::kernel32::STARTUPINFO>::GuestAllocation() {
    using namespace windows;
    using namespace windows::kernel32;

    auto& domain = Domain::thread_local_domain();
    auto* guest = static_cast<windows::WindowsGuest*>(domain.guest());
    assert(guest != nullptr);

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
    const size_t structure_size =
        (x64) ? sizeof(structs::_STARTUPINFO<uint64_t>) : sizeof(structs::_STARTUPINFO<uint32_t>);

    // Allocate memory for the size of the structure plus the size of the string
    buffer_.emplace(structure_size);

    // Zero it
    memset(buffer_->get(), 0, structure_size);

    // Create the structure
    value_ = STARTUPINFO::make_unique(buffer_->address());

    // The _STARTUPINFO struct's cb member is the "count of bytes".
    // It just needs to be the struct size for Windows to accept it.
    value_->cb(structure_size);
}

} // namespace inject
} // namespace introvirt