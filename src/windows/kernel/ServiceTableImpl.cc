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
#include "ServiceTableImpl.hh"

namespace introvirt {
namespace windows {

template <typename PtrType>
GuestVirtualAddress ServiceTableImpl<PtrType>::entry(unsigned int index) const {
    if constexpr (std::is_same_v<uint64_t, PtrType>) {
        // With 64-bit, the value is relative to the start of the table
        return gva_ + (table_[index] >> 4);
    } else {
        // With 32-bit, the table directly holds the address
        return gva_.create(table_[index]);
    }
}

template <typename PtrType>
unsigned int ServiceTableImpl<PtrType>::length() const {
    return table_.length();
}

template <typename PtrType>
ServiceTableImpl<PtrType>::ServiceTableImpl(const GuestVirtualAddress& gva, unsigned int length)
    : gva_(gva), table_(gva, length) {}

// Explicit template instantiation
template class ServiceTableImpl<uint32_t>;
template class ServiceTableImpl<uint64_t>;

} // namespace windows
} // namespace introvirt