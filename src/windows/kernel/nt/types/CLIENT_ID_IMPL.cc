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

#include "CLIENT_ID_IMPL.hh"

#include <introvirt/windows/WindowsGuest.hh>
#include <introvirt/windows/kernel/nt/NtKernel.hh>

namespace introvirt {
namespace windows {
namespace nt {

std::unique_ptr<CLIENT_ID> CLIENT_ID::make_unique(const NtKernel& kernel,
                                                  const guest_ptr<void>& ptr) {

    if (kernel.x64()) {
        return std::make_unique<CLIENT_ID_IMPL<uint64_t>>(ptr);
    } else {
        return std::make_unique<CLIENT_ID_IMPL<uint32_t>>(ptr);
    }
}

std::ostream& operator<<(std::ostream& os, const CLIENT_ID& cid) {
    boost::io::ios_flags_saver ifs(os);
    os << '[' << cid.UniqueProcess() << ':' << cid.UniqueThread() << "]";
    return os;
}

} /* namespace nt */
} /* namespace windows */

namespace inject {

GuestAllocation<windows::nt::CLIENT_ID>::GuestAllocation() : GuestAllocation(0, 0) {}

GuestAllocation<windows::nt::CLIENT_ID>::GuestAllocation(uint64_t UniqueProcess,
                                                         uint64_t UniqueThread) {

    using namespace windows::nt;

    auto& domain = Domain::thread_local_domain();
    auto* guest = static_cast<windows::WindowsGuest*>(domain.guest());
    introvirt_assert(guest != nullptr, "");
    auto& kernel = guest->kernel();

    // Get the size required for the structure
    const size_t structure_size = (kernel.x64()) ? sizeof(structs::_CLIENT_ID<uint64_t>)
                                                 : sizeof(structs::_CLIENT_ID<uint32_t>);

    // Allocate memory for the size of the structure plus the size of the string
    allocation_.emplace(structure_size);

    // Create the structure
    value_ = CLIENT_ID::make_unique(kernel, allocation_->ptr());
    value_->UniqueProcess(UniqueProcess);
    value_->UniqueThread(UniqueThread);
}

} /* namespace inject */
} /* namespace introvirt */
