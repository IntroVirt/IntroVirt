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
#include "INITIAL_TEB_IMPL.hh"

#include <introvirt/windows/kernel/nt/NtKernel.hh>

#include <boost/io/ios_state.hpp>

namespace introvirt {
namespace windows {
namespace nt {

template <typename PtrType>
void INITIAL_TEB_IMPL<PtrType>::write(std::ostream& os, const std::string& linePrefix) const {
    boost::io::ios_flags_saver ifs(os);
    os << std::hex;
    os << linePrefix << "StackBase:      0x" << StackBase() << '\n';
    os << linePrefix << "StackLimit:     0x" << StackLimit() << '\n';
    os << linePrefix << "StackCommit:    0x" << StackCommit() << '\n';
    os << linePrefix << "StackCommitMax: 0x" << StackCommitMax() << '\n';
    os << linePrefix << "StackReserved:  0x" << StackReserved() << '\n';
}

template <typename PtrType>
Json::Value INITIAL_TEB_IMPL<PtrType>::json() const {
    Json::Value result;
    result["StackBase"] = StackBase();
    result["StackLimit"] = StackLimit();
    result["StackCommit"] = StackCommit();
    result["StackCommitMax"] = StackCommitMax();
    result["StackReserved"] = StackReserved();
    return result;
}

std::unique_ptr<INITIAL_TEB> INITIAL_TEB::make_unique(const NtKernel& kernel,
                                                      const GuestVirtualAddress& gva) {

    if (kernel.x64())
        return std::make_unique<INITIAL_TEB_IMPL<uint64_t>>(gva);
    else
        return std::make_unique<INITIAL_TEB_IMPL<uint32_t>>(gva);
}

} // namespace nt
} // namespace windows
} // namespace introvirt