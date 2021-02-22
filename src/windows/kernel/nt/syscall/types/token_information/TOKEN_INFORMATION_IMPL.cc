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
#include "TOKEN_INFORMATION_IMPL.hh"

#include "TOKEN_GROUPS_IMPL.hh"
#include "TOKEN_IS_APP_CONTAINER_IMPL.hh"
#include "TOKEN_OWNER_IMPL.hh"
#include "TOKEN_PRIVILEGES_IMPL.hh"
#include "TOKEN_USER_IMPL.hh"

#include <introvirt/windows/kernel/nt/NtKernel.hh>

namespace introvirt {
namespace windows {
namespace nt {

template <typename PtrType>
static std::unique_ptr<TOKEN_INFORMATION>
make_unique_impl(const NtKernel& kernel, TOKEN_INFORMATION_CLASS information_class,
                 const GuestVirtualAddress& gva, uint32_t buffer_size) {

    // TODO(pape): Implement missing types
    switch (information_class) {
    case TOKEN_INFORMATION_CLASS::TokenGroups:
        return std::make_unique<TOKEN_GROUPS_IMPL<PtrType>>(gva, buffer_size);
    case TOKEN_INFORMATION_CLASS::TokenOwner:
        return std::make_unique<TOKEN_OWNER_IMPL<PtrType>>(gva, buffer_size);
    case TOKEN_INFORMATION_CLASS::TokenPrivileges:
        return std::make_unique<TOKEN_PRIVILEGES_IMPL>(gva, buffer_size);
    case TOKEN_INFORMATION_CLASS::TokenUser:
        return std::make_unique<TOKEN_USER_IMPL<PtrType>>(gva, buffer_size);
    case TOKEN_INFORMATION_CLASS::TokenIsAppContainer:
        return std::make_unique<TOKEN_IS_APP_CONTAINER_IMPL>(gva, buffer_size);
    }

    return std::make_unique<TOKEN_INFORMATION_IMPL<>>(information_class, gva, buffer_size);
}

std::unique_ptr<TOKEN_INFORMATION>
TOKEN_INFORMATION::make_unique(const NtKernel& kernel, TOKEN_INFORMATION_CLASS information_class,
                               const GuestVirtualAddress& gva, uint32_t buffer_size) {

    if (unlikely(buffer_size == 0))
        return nullptr;

    if (kernel.x64())
        return make_unique_impl<uint64_t>(kernel, information_class, gva, buffer_size);
    else
        return make_unique_impl<uint32_t>(kernel, information_class, gva, buffer_size);
}

} // namespace nt
} // namespace windows
} // namespace introvirt