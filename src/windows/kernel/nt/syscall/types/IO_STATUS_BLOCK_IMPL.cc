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
#include "IO_STATUS_BLOCK_IMPL.hh"
#include "core/event/EventImpl.hh"

#include <introvirt/windows/WindowsGuest.hh>
#include <introvirt/windows/kernel/nt/NtKernel.hh>

#include <boost/io/ios_state.hpp>

namespace introvirt {
namespace windows {
namespace nt {

template <typename PtrType>
void IO_STATUS_BLOCK_IMPL<PtrType>::write(std::ostream& os, const std::string& linePrefix) const {
    boost::io::ios_flags_saver ifs(os);
    // TODO: Determine more context here. Pointer/Status are in a union.
    os << std::hex;
    os << linePrefix << "Pointer/Status: 0x" << Pointer() << '\n';
    os << linePrefix << "Information: 0x" << Information() << '\n';
}

template <typename PtrType>
Json::Value IO_STATUS_BLOCK_IMPL<PtrType>::json() const {
    Json::Value result;

    result["Pointer"] = Pointer();
    result["Status"] = Status();
    result["Information"] = Information();

    return result;
}

std::unique_ptr<IO_STATUS_BLOCK> IO_STATUS_BLOCK::make_unique(const NtKernel& kernel,
                                                              const GuestVirtualAddress& gva) {

    if (kernel.x64()) {
        return std::make_unique<IO_STATUS_BLOCK_IMPL<uint64_t>>(gva);
    } else {
        return std::make_unique<IO_STATUS_BLOCK_IMPL<uint32_t>>(gva);
    }
}

template class IO_STATUS_BLOCK_IMPL<uint32_t>;
template class IO_STATUS_BLOCK_IMPL<uint64_t>;

} /* namespace nt */
} /* namespace windows */

namespace inject {

GuestAllocation<windows::nt::IO_STATUS_BLOCK>::GuestAllocation() {
    using namespace windows;
    using namespace windows::nt;

    auto& domain = Domain::thread_local_domain();
    auto* guest = static_cast<windows::WindowsGuest*>(domain.guest());
    assert(guest != nullptr);
    auto& kernel = guest->kernel();

    // Get the size required for the structure
    const size_t structure_size = kernel.x64() ? sizeof(structs::_IO_STATUS_BLOCK<uint64_t>)
                                               : sizeof(structs::_IO_STATUS_BLOCK<uint32_t>);

    // Allocate memory for the size of the structure plus the size of the string
    buffer_.emplace(structure_size);

    // Zero the buffer
    memset(buffer_->get(), 0, structure_size);

    // Create the string
    if (kernel.x64()) {
        value_ = std::make_unique<IO_STATUS_BLOCK_IMPL<uint64_t>>(buffer_->address());
    } else {
        value_ = std::make_unique<IO_STATUS_BLOCK_IMPL<uint32_t>>(buffer_->address());
    }
}

} // namespace inject
} // namespace introvirt
