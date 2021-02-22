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

#include "PS_ATTRIBUTE_IMPL.hh"
#include "windows/kernel/nt/syscall/types/array_iterable.hh"

#include <introvirt/core/memory/guest_ptr.hh>
#include <introvirt/windows/kernel/nt/syscall/types/PS_ATTRIBUTE_LIST.hh>

namespace introvirt {
namespace windows {
namespace nt {

namespace structs {

template <typename PtrType>
struct _PS_ATTRIBUTE_LIST {
    PtrType TotalLength;
    _PS_ATTRIBUTE<PtrType> Attributes[];
};
} // namespace structs

template <typename PtrType>
class PS_ATTRIBUTE_LIST_IMPL final
    : public array_iterable<PS_ATTRIBUTE_IMPL<PtrType>, PS_ATTRIBUTE_LIST,
                            sizeof(structs::_PS_ATTRIBUTE<PtrType>), PtrType, true,
                            offsetof(structs::_PS_ATTRIBUTE_LIST<PtrType>, Attributes)> {
  public:
    GuestVirtualAddress address() const override { return gva_; }

    uint32_t buffer_size() const override { return buffer_size_; }

    void write(std::ostream& os, const std::string& linePrefix = "") const override;

    Json::Value json() const override;

    PS_ATTRIBUTE_LIST_IMPL(const GuestVirtualAddress& gva);

  private:
    using array_iterable_type = array_iterable<PS_ATTRIBUTE_IMPL<PtrType>, PS_ATTRIBUTE_LIST,
                                               sizeof(structs::_PS_ATTRIBUTE<PtrType>), PtrType,
                                               true, sizeof(structs::_PS_ATTRIBUTE_LIST<PtrType>)>;

    const GuestVirtualAddress gva_;
    const PtrType buffer_size_;
};

} // namespace nt
} // namespace windows
} // namespace introvirt