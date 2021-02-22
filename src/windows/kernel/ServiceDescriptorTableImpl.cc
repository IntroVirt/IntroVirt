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
#include "ServiceDescriptorTableImpl.hh"
#include <introvirt/core/memory/guest_ptr.hh>
#include <introvirt/windows/kernel/nt/NtKernel.hh>

#include <log4cxx/logger.h>

namespace introvirt {
namespace windows {

static log4cxx::LoggerPtr
    logger(log4cxx::Logger::getLogger("introvirt.windows.kernel.ServiceDescriptorTable"));

template <typename PtrType>
struct ServiceDescriptorEntry {
    PtrType ServiceTable;
    PtrType CounterTable; // Unused generally
    PtrType ServiceLimit;
    PtrType ArgumentTable;
};

template <typename PtrType>
const ServiceTableImpl<PtrType>& ServiceDescriptorTableEntryImpl<PtrType>::service_table() const {
    return service_table_;
}

template <typename PtrType>
ServiceDescriptorTableEntryImpl<PtrType>::ServiceDescriptorTableEntryImpl(
    const GuestVirtualAddress& p_service_table, PtrType count)
    : service_table_(p_service_table, count) {}

template <typename PtrType>
const ServiceDescriptorTableEntry&
ServiceDescriptorTableImpl<PtrType>::entry(unsigned int index) const {
    return entries_[index];
}

template <typename PtrType>
unsigned int ServiceDescriptorTableImpl<PtrType>::count() const {
    return entries_.size();
}

template <typename PtrType>
ServiceDescriptorTableImpl<PtrType>::ServiceDescriptorTableImpl(GuestVirtualAddress gva) {

    guest_ptr<ServiceDescriptorEntry<PtrType>> entry(gva);
    while (entry->ServiceTable && entry->ServiceLimit && count() < 2) {
        entries_.emplace_back(gva.create(entry->ServiceTable), entry->ServiceLimit);

        gva += sizeof(ServiceDescriptorEntry<PtrType>);
        entry.reset(gva);
    }
}

std::unique_ptr<ServiceDescriptorTable>
ServiceDescriptorTable::create(const nt::NtKernel& kernel, const GuestVirtualAddress& gva) {
    if (kernel.x64()) {
        return std::make_unique<ServiceDescriptorTableImpl<uint64_t>>(gva);
    } else {
        return std::make_unique<ServiceDescriptorTableImpl<uint32_t>>(gva);
    }
}

// Explicit template instantiation

template class ServiceDescriptorTableImpl<uint32_t>;
template class ServiceDescriptorTableImpl<uint64_t>;

} // namespace windows
} // namespace introvirt