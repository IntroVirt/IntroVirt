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
#include "MEMORY_BASIC_INFORMATION_IMPL.hh"

#include <introvirt/windows/WindowsGuest.hh>
#include <introvirt/windows/kernel/nt/NtKernel.hh>

#include <boost/io/ios_state.hpp>

namespace introvirt {
namespace windows {
namespace nt {

template <typename PtrType>
void MEMORY_BASIC_INFORMATION_IMPL<PtrType>::write(std::ostream& os,
                                                   const std::string& linePrefix) const {
    MEMORY_INFORMATION_IMPL_BASE<PtrType>::write(os, linePrefix);

    boost::io::ios_flags_saver ifs(os);
    os << std::hex;
    os << linePrefix << "BaseAddress: 0x" << BaseAddress() << '\n';
    os << linePrefix << "AllocationBase: 0x" << AllocationBase() << '\n';
    os << linePrefix << "AllocationProtect: " << AllocationProtect().string() << '\n';
    os << linePrefix << "RegionSize: 0x" << RegionSize() << '\n';
    os << linePrefix << "State: " << State().string() << '\n';
    os << linePrefix << "Protect: " << Protect().string() << '\n';
    os << linePrefix << "Type: " << Type().string() << '\n';
}

template <typename PtrType>
Json::Value MEMORY_BASIC_INFORMATION_IMPL<PtrType>::json() const {
    Json::Value result = MEMORY_INFORMATION_IMPL_BASE<PtrType>::json();

    result["BaseAddress"] = BaseAddress();
    result["AllocationBase"] = AllocationBase();
    result["AllocationProtect"] = AllocationProtect().value();
    result["RegionSize"] = RegionSize();
    result["State"] = State().value();
    result["Protect"] = Protect().value();
    result["Type"] = Type().value();

    return result;
}

template <typename PtrType>
MEMORY_BASIC_INFORMATION_IMPL<PtrType>::MEMORY_BASIC_INFORMATION_IMPL(
    const GuestVirtualAddress& gva, uint32_t buffer_size)
    : MEMORY_INFORMATION_IMPL_BASE<PtrType>(MEMORY_INFORMATION_CLASS::MemoryBasicInformation, gva,
                                            buffer_size) {}

std::unique_ptr<MEMORY_BASIC_INFORMATION>
MEMORY_BASIC_INFORMATION::make_unique(const NtKernel& kernel, const GuestVirtualAddress& gva,
                                      uint32_t buffer_size) {
    if (kernel.x64()) {
        return std::make_unique<nt::MEMORY_BASIC_INFORMATION_IMPL<uint64_t>>(gva, buffer_size);
    } else {
        return std::make_unique<nt::MEMORY_BASIC_INFORMATION_IMPL<uint32_t>>(gva, buffer_size);
    }
}

template class MEMORY_BASIC_INFORMATION_IMPL<uint32_t>;
template class MEMORY_BASIC_INFORMATION_IMPL<uint64_t>;

} // namespace nt
} // namespace windows

namespace inject {

GuestAllocation<windows::nt::MEMORY_BASIC_INFORMATION>::GuestAllocation() {
    using namespace windows;
    using namespace windows::nt;

    auto& domain = Domain::thread_local_domain();
    auto* guest = static_cast<WindowsGuest*>(domain.guest());
    assert(guest != nullptr);

    if (guest->x64()) {
        constexpr uint32_t buffer_size = sizeof(structs::_MEMORY_BASIC_INFORMATION<uint64_t>);
        buffer_.emplace(buffer_size);
        value_ = std::make_unique<MEMORY_BASIC_INFORMATION_IMPL<uint64_t>>(*buffer_, buffer_size);
    } else {
        constexpr uint32_t buffer_size = sizeof(structs::_MEMORY_BASIC_INFORMATION<uint32_t>);
        buffer_.emplace(buffer_size);
        value_ = std::make_unique<MEMORY_BASIC_INFORMATION_IMPL<uint32_t>>(*buffer_, buffer_size);
    }
}

} // namespace inject
} // namespace introvirt