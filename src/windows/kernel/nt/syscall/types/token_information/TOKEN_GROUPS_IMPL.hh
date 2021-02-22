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

#include "TOKEN_INFORMATION_IMPL.hh"

#include "windows/kernel/nt/syscall/types/array_iterable.hh"
#include "windows/kernel/nt/types/SID_AND_ATTRIBUTES_IMPL.hh"

#include <introvirt/core/memory/guest_ptr.hh>
#include <introvirt/windows/kernel/nt/syscall/types/token_information/TOKEN_GROUPS.hh>

#include <mutex>
#include <optional>
#include <vector>

namespace introvirt {
namespace windows {
namespace nt {

namespace structs {

template <typename PtrType>
struct _TOKEN_GROUPS {
    uint32_t GroupCount;
    _SID_AND_ATTRIBUTES<PtrType> Groups[];
};

static_assert(sizeof(_TOKEN_GROUPS<uint32_t>) == 4);
static_assert(sizeof(_TOKEN_GROUPS<uint64_t>) == 8);

} // namespace structs

template <typename PtrType>
class TOKEN_GROUPS_IMPL final
    : public array_iterable<SID_AND_ATTRIBUTES_IMPL<PtrType>,
                            TOKEN_INFORMATION_IMPL<TOKEN_GROUPS, structs::_TOKEN_GROUPS<PtrType>>,
                            sizeof(structs::_SID_AND_ATTRIBUTES<PtrType>)> {
  public:
    void write(std::ostream& os, const std::string& linePrefix = "") const override;

    Json::Value json() const override;

    TOKEN_GROUPS_IMPL(const GuestVirtualAddress& gva, uint32_t buffer_size);

  private:
    using array_iterable_type =
        array_iterable<SID_AND_ATTRIBUTES_IMPL<PtrType>,
                       TOKEN_INFORMATION_IMPL<TOKEN_GROUPS, structs::_TOKEN_GROUPS<PtrType>>,
                       sizeof(structs::_SID_AND_ATTRIBUTES<PtrType>)>;
    using TOKEN_INFORMATION_IMPL_TYPE =
        TOKEN_INFORMATION_IMPL<TOKEN_GROUPS, structs::_TOKEN_GROUPS<PtrType>>;
};

} // namespace nt
} // namespace windows
} // namespace introvirt