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
#include "THREAD_BASIC_INFORMATION_IMPL.hh"

#include <boost/io/ios_state.hpp>

namespace introvirt {
namespace windows {
namespace nt {

template <typename PtrType>
void THREAD_BASIC_INFORMATION_IMPL<PtrType>::write(std::ostream& os,
                                                   const std::string& linePrefix) const {

    THREAD_BASIC_INFORMATION_IMPL_BASE<PtrType>::write(os, linePrefix);

    boost::io::ios_flags_saver ifs(os);
    os << std::dec;

    os << linePrefix << "ExitStatus: " << ExitStatus() << '\n';
    os << linePrefix << "TebBaseAddress: 0x" << std::hex << TebBaseAddress() << std::dec << '\n';
    os << linePrefix << "ClientId:\n";
    ClientId().write(os, linePrefix + "  ");
    os << linePrefix << "AffinityMask: 0x" << std::hex << AffinityMask() << std::dec << '\n';
    os << linePrefix << "Priority: " << Priority() << '\n';
    os << linePrefix << "BasePriority: " << BasePriority() << '\n';
}

template <typename PtrType>
Json::Value THREAD_BASIC_INFORMATION_IMPL<PtrType>::json() const {
    Json::Value result = THREAD_BASIC_INFORMATION_IMPL_BASE<PtrType>::json();

    result["ExitStatus"] = ExitStatus();
    result["TebBaseAddress"] = TebBaseAddress();
    result["ClientId"] = ClientId().json();
    result["AffinityMask"] = AffinityMask();
    result["Priority"] = Priority();
    result["BasePriority"] = BasePriority();

    return result;
}

template class THREAD_BASIC_INFORMATION_IMPL<uint32_t>;
template class THREAD_BASIC_INFORMATION_IMPL<uint64_t>;

} // namespace nt
} // namespace windows
} // namespace introvirt