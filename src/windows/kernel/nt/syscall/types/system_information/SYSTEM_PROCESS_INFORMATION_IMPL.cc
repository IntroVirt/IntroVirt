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
#include "SYSTEM_PROCESS_INFORMATION_IMPL.hh"

namespace introvirt {
namespace windows {
namespace nt {

template <typename PtrType>
void SYSTEM_PROCESS_INFORMATION_IMPL<PtrType>::write(std::ostream& os,
                                                     const std::string& linePrefix) const {

    SYSTEM_PROCESS_INFORMATION_IMPL_BASE<PtrType>::write(os, linePrefix);
    for (auto& entry : *this) {
        entry.write(os, linePrefix + "  ");
    }
}

template <typename PtrType>
Json::Value SYSTEM_PROCESS_INFORMATION_IMPL<PtrType>::json() const {
    Json::Value result = SYSTEM_PROCESS_INFORMATION_IMPL_BASE<PtrType>::json();

    Json::Value entries;
    for (auto& entry : *this) {
        entries.append(entry.json());
    }

    return result;
}

template class SYSTEM_PROCESS_INFORMATION_IMPL<uint32_t>;
template class SYSTEM_PROCESS_INFORMATION_IMPL<uint64_t>;

} // namespace nt
} // namespace windows
} // namespace introvirt