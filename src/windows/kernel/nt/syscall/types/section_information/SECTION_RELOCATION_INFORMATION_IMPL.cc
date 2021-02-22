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
#include "SECTION_RELOCATION_INFORMATION_IMPL.hh"

#include <boost/io/ios_state.hpp>

namespace introvirt {
namespace windows {
namespace nt {

template <typename PtrType>
void SECTION_RELOCATION_INFORMATION_IMPL<PtrType>::write(std::ostream& os,
                                                         const std::string& linePrefix) const {

    SECTION_RELOCATION_INFORMATION_IMPL_BASE<PtrType>::write(os, linePrefix);

    boost::io::ios_flags_saver ifs(os);
    os << std::hex;

    os << linePrefix << "BaseAddress: 0x" << BaseAddress() << '\n';
}

template <typename PtrType>
Json::Value SECTION_RELOCATION_INFORMATION_IMPL<PtrType>::json() const {
    Json::Value result = SECTION_RELOCATION_INFORMATION_IMPL_BASE<PtrType>::json();

    result["BaseAddress"] = BaseAddress();

    return result;
}

template class SECTION_RELOCATION_INFORMATION_IMPL<uint32_t>;
template class SECTION_RELOCATION_INFORMATION_IMPL<uint64_t>;

} // namespace nt
} // namespace windows
} // namespace introvirt