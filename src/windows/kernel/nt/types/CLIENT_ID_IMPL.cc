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

#include <introvirt/core/memory/guest_ptr.hh>
#include <introvirt/windows/WindowsGuest.hh>
#include <introvirt/windows/kernel/nt/NtKernel.hh>

#include <boost/io/ios_state.hpp>

namespace introvirt {
namespace windows {
namespace nt {

template <typename PtrType>
void CLIENT_ID_IMPL<PtrType>::write(std::ostream& os, const std::string& linePrefix) const {
    boost::io::ios_flags_saver ifs(os);
    os << std::dec;
    os << linePrefix << *this << '\n';
}

template <typename PtrType>
Json::Value CLIENT_ID_IMPL<PtrType>::json() const {
    Json::Value result;
    result["UniqueProcess"] = UniqueProcess();
    result["UniqueThread"] = UniqueThread();
    return result;
}

template <typename PtrType>
CLIENT_ID_IMPL<PtrType>::operator Json::Value() const {
    return json();
}

template <typename PtrType>
uint64_t CLIENT_ID_IMPL<PtrType>::UniqueProcess() const {
    return client_id_->UniqueProcess;
}
template <typename PtrType>
uint64_t CLIENT_ID_IMPL<PtrType>::UniqueThread() const {
    return client_id_->UniqueThread;
}

template <typename PtrType>
void CLIENT_ID_IMPL<PtrType>::UniqueProcess(uint64_t UniqueProcess) {
    client_id_->UniqueProcess = UniqueProcess;
}

template <typename PtrType>
void CLIENT_ID_IMPL<PtrType>::UniqueThread(uint64_t UniqueThread) {
    client_id_->UniqueThread = UniqueThread;
}

template <typename PtrType>
GuestVirtualAddress CLIENT_ID_IMPL<PtrType>::address() const {
    return gva_;
}

template <typename PtrType>
CLIENT_ID_IMPL<PtrType>::CLIENT_ID_IMPL(const GuestVirtualAddress& gva)
    : gva_(gva), client_id_(gva_) {}

std::unique_ptr<CLIENT_ID> CLIENT_ID::make_unique(const NtKernel& kernel,
                                                  const GuestVirtualAddress& gva) {

    if (kernel.x64()) {
        return std::make_unique<CLIENT_ID_IMPL<uint64_t>>(gva);
    } else {
        return std::make_unique<CLIENT_ID_IMPL<uint32_t>>(gva);
    }
}

std::ostream& operator<<(std::ostream& os, const CLIENT_ID& cid) {
    boost::io::ios_flags_saver ifs(os);
    os << '[' << cid.UniqueProcess() << ':' << cid.UniqueThread() << "]";
    return os;
}

// Explicit template instantiation
template class CLIENT_ID_IMPL<uint32_t>;
template class CLIENT_ID_IMPL<uint64_t>;

} /* namespace nt */
} /* namespace windows */

namespace inject {

GuestAllocation<windows::nt::CLIENT_ID>::GuestAllocation() : GuestAllocation(0, 0) {}

GuestAllocation<windows::nt::CLIENT_ID>::GuestAllocation(uint64_t UniqueProcess,
                                                         uint64_t UniqueThread) {

    using namespace windows::nt;

    auto& domain = Domain::thread_local_domain();
    auto* guest = static_cast<windows::WindowsGuest*>(domain.guest());
    assert(guest != nullptr);
    auto& kernel = guest->kernel();

    // Get the size required for the structure
    const size_t structure_size = (kernel.x64()) ? sizeof(structs::_CLIENT_ID<uint64_t>)
                                                 : sizeof(structs::_CLIENT_ID<uint32_t>);

    // Allocate memory for the size of the structure plus the size of the string
    buffer_.emplace(structure_size);

    // Create the structure
    value_ = CLIENT_ID::make_unique(kernel, *buffer_);
    value_->UniqueProcess(UniqueProcess);
    value_->UniqueThread(UniqueThread);
}

} /* namespace inject */
} /* namespace introvirt */
