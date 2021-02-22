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
#include "windows/kernel/nt/types/LUID_AND_ATTRIBUTES_IMPL.hh"

#include <introvirt/windows/kernel/nt/syscall/types/token_information/TOKEN_PRIVILEGES.hh>

#include <mutex>
#include <optional>
#include <vector>

namespace introvirt {
namespace windows {
namespace nt {

namespace structs {

struct __attribute__((packed)) _TOKEN_PRIVILEGES {
    uint32_t PrivilegeCount;
    struct _LUID_AND_ATTRIBUTES Privileges[];
};

static_assert(sizeof(_TOKEN_PRIVILEGES) == 0x4);

} // namespace structs

class TOKEN_PRIVILEGES_IMPL final
    : public array_iterable<LUID_AND_ATTRIBUTES_IMPL,
                            TOKEN_INFORMATION_IMPL<TOKEN_PRIVILEGES, structs::_TOKEN_PRIVILEGES>,
                            sizeof(structs::_LUID_AND_ATTRIBUTES)> {
  public:
    void write(std::ostream& os, const std::string& linePrefix = "") const override;

    Json::Value json() const override;

    TOKEN_PRIVILEGES_IMPL(const GuestVirtualAddress& gva);
    TOKEN_PRIVILEGES_IMPL(const GuestVirtualAddress& gva, uint32_t buffer_size);

  private:
    using array_iterable_type =
        array_iterable<LUID_AND_ATTRIBUTES_IMPL,
                       TOKEN_INFORMATION_IMPL<TOKEN_PRIVILEGES, structs::_TOKEN_PRIVILEGES>,
                       sizeof(structs::_LUID_AND_ATTRIBUTES)>;

    using TOKEN_INFORMATION_IMPL_TYPE =
        TOKEN_INFORMATION_IMPL<TOKEN_PRIVILEGES, structs::_TOKEN_PRIVILEGES>;
};

} // namespace nt
} // namespace windows
} // namespace introvirt