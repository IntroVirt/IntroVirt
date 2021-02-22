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

#include <introvirt/core/memory/guest_ptr.hh>
#include <introvirt/windows/kernel/ServiceTable.hh>

namespace introvirt {
namespace windows {

template <typename PtrType>
class ServiceTableImpl final : public ServiceTable {
  public:
    GuestVirtualAddress entry(unsigned int index) const override;
    unsigned int length() const override;

    ServiceTableImpl(const GuestVirtualAddress& gva, unsigned int length);

  private:
    GuestVirtualAddress gva_;
    guest_ptr<int32_t[]> table_;
};

} // namespace windows
} // namespace introvirt