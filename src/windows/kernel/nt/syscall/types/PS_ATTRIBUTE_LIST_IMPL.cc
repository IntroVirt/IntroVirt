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
#include "PS_ATTRIBUTE_LIST_IMPL.hh"

#include <introvirt/core/exception/BufferTooSmallException.hh>
#include <introvirt/util/compiler.hh>
#include <introvirt/windows/kernel/nt/NtKernel.hh>

namespace introvirt {
namespace windows {
namespace nt {

template <typename PtrType>
void PS_ATTRIBUTE_LIST_IMPL<PtrType>::write(std::ostream& os, const std::string& linePrefix) const {
    os << linePrefix << "Length: " << this->length() << '\n';
    for (auto& entry : *this) {
        entry.write(os, linePrefix + "  ");
    }
}

template <typename PtrType>
Json::Value PS_ATTRIBUTE_LIST_IMPL<PtrType>::json() const {
    Json::Value entries;
    for (auto& entry : *this) {
        entries.append(entry.json());
    }
    Json::Value result;
    result["entries"] = std::move(entries);
    return result;
}

template <typename PtrType>
PS_ATTRIBUTE_LIST_IMPL<PtrType>::PS_ATTRIBUTE_LIST_IMPL(const GuestVirtualAddress& gva)
    : array_iterable_type(gva, gva + offsetof(structs::_PS_ATTRIBUTE_LIST<PtrType>, Attributes)),
      gva_(gva),
      buffer_size_(array_iterable_type::length() * sizeof(structs::_PS_ATTRIBUTE<PtrType>)) {}

std::unique_ptr<PS_ATTRIBUTE_LIST> PS_ATTRIBUTE_LIST::make_unique(const NtKernel& kernel,
                                                                  const GuestVirtualAddress& gva) {
    if (kernel.x64())
        return std::make_unique<PS_ATTRIBUTE_LIST_IMPL<uint64_t>>(gva);
    else
        return std::make_unique<PS_ATTRIBUTE_LIST_IMPL<uint32_t>>(gva);
}

template class PS_ATTRIBUTE_LIST_IMPL<uint32_t>;
template class PS_ATTRIBUTE_LIST_IMPL<uint64_t>;

} // namespace nt
} // namespace windows
} // namespace introvirt
