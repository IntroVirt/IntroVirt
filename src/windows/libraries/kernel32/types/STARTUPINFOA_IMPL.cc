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
#include "STARTUPINFOA_IMPL.hh"
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

std::shared_ptr<STARTUPINFOA> STARTUPINFOA::make_shared(const guest_ptr<void>& ptr, bool x64) {
    if (x64) {
        return std::make_shared<STARTUPINFOA_IMPL<uint64_t>>(ptr);
    } else {
        return std::make_shared<STARTUPINFOA_IMPL<uint32_t>>(ptr);
    }
}

} // namespace kernel32
} // namespace windows

namespace inject {

GuestAllocation<windows::kernel32::STARTUPINFOA>::GuestAllocation() {
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
    const size_t structure_size =
        (x64) ? sizeof(structs::_STARTUPINFOA<uint64_t>) : sizeof(structs::_STARTUPINFOA<uint32_t>);

    // Allocate memory for the size of the structure plus the size of the string
    allocation_.emplace(structure_size);
    auto& ptr = allocation_->ptr();

    // Zero it
    memset(ptr.get(), 0, structure_size);

    // Create the structure
    value_ = STARTUPINFOA::make_shared(ptr, x64);

    // The _STARTUPINFOA struct's cb member is the "count of bytes".
    // It just needs to be the struct size for Windows to accept it.
    value_->cb(structure_size);
}

} // namespace inject
} // namespace introvirt