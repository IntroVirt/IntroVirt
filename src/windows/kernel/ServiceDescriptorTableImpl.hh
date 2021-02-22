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
#pragma once

#include "ServiceTableImpl.hh"
#include <introvirt/windows/kernel/ServiceDescriptorTable.hh>

namespace introvirt {
namespace windows {

template <typename PtrType>
class ServiceDescriptorTableEntryImpl final : public ServiceDescriptorTableEntry {
  public:
    const ServiceTableImpl<PtrType>& service_table() const override;

    ServiceDescriptorTableEntryImpl(const GuestVirtualAddress& p_service_table, PtrType count);

  private:
    ServiceTableImpl<PtrType> service_table_;
};

template <typename PtrType>
class ServiceDescriptorTableImpl final : public ServiceDescriptorTable {
  public:
    const ServiceDescriptorTableEntry& entry(unsigned int index) const override;

    unsigned int count() const override;

    ServiceDescriptorTableImpl(GuestVirtualAddress gva);

  private:
    std::vector<ServiceDescriptorTableEntryImpl<PtrType>> entries_;
};

} // namespace windows
} // namespace introvirt