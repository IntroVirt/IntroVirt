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
#include "TOKEN_IMPL.hh"
#include "windows/kernel/nt/NtKernelImpl.hh"

#include <introvirt/util/compiler.hh>
#include <introvirt/windows/kernel/nt/NtKernel.hh>
#include <introvirt/windows/kernel/nt/const/ObjectType.hh>
#include <introvirt/windows/kernel/nt/types/objects/OBJECT_HEADER.hh>
#include <introvirt/windows/kernel/nt/types/objects/OBJECT_TYPE.hh>

#include <log4cxx/logger.h>

#include <cstring>
#include <sstream>
#include <string>

namespace introvirt {
namespace windows {
namespace nt {

static log4cxx::LoggerPtr
    logger(log4cxx::Logger::getLogger("introvirt.windows.kernel.nt.types.TOKEN"));

template <typename PtrType>
std::vector<std::shared_ptr<SID_AND_ATTRIBUTES>> TOKEN_IMPL<PtrType>::Groups() {
    return groups_;
}

template <typename PtrType>
std::vector<std::shared_ptr<const SID_AND_ATTRIBUTES>> TOKEN_IMPL<PtrType>::Groups() const {
    std::vector<std::shared_ptr<const SID_AND_ATTRIBUTES>> result;
    for (const auto& group : groups_) {
        result.push_back(std::const_pointer_cast<const SID_AND_ATTRIBUTES>(group));
    }
    return result;
}

template <typename PtrType>
const SID* TOKEN_IMPL<PtrType>::User() const {
    if (likely(user_.has_value()))
        return user_->Sid();
    return nullptr;
}

template <typename PtrType>
const SID* TOKEN_IMPL<PtrType>::PrimaryGroup() const {
    if (likely(primary_group_.has_value()))
        return &(*primary_group_);
    return nullptr;
}

template <typename PtrType>
uint64_t TOKEN_IMPL<PtrType>::PrivilegesPresent() const {
    const auto* privs = LoadOffsets<structs::SEP_TOKEN_PRIVILEGES>(kernel_);
    const auto offset = token->Privileges.offset();

    return privs->Present.template get<uint64_t>(buffer.get() + offset);
}

template <typename PtrType>
void TOKEN_IMPL<PtrType>::PrivilegesPresent(uint64_t Privileges) {
    const auto* privs = LoadOffsets<structs::SEP_TOKEN_PRIVILEGES>(kernel_);
    const auto offset = token->Privileges.offset();

    return privs->Present.template set<uint64_t>(buffer.get() + offset, Privileges);
}

template <typename PtrType>
uint64_t TOKEN_IMPL<PtrType>::PrivilegesEnabled() const {
    const auto* privs = LoadOffsets<structs::SEP_TOKEN_PRIVILEGES>(kernel_);
    const auto offset = token->Privileges.offset();

    return privs->Enabled.template get<uint64_t>(buffer.get() + offset);
}

template <typename PtrType>
void TOKEN_IMPL<PtrType>::PrivilegesEnabled(uint64_t Privileges) {
    const auto* privs = LoadOffsets<structs::SEP_TOKEN_PRIVILEGES>(kernel_);
    const auto offset = token->Privileges.offset();

    return privs->Enabled.template set<uint64_t>(buffer.get() + offset, Privileges);
}

template <typename PtrType>
void TOKEN_IMPL<PtrType>::init(const NtKernelImpl<PtrType>& kernel,
                               const GuestVirtualAddress& gva) {
    // Load offsets
    token = LoadOffsets<structs::TOKEN>(kernel);
    auto sid_and_attributes = LoadOffsets<structs::SID_AND_ATTRIBUTES>(kernel);

    // Map in the structure
    buffer.reset(gva, token->size());

    const uint32_t UserAndGroupCount = token->UserAndGroupCount.get<uint32_t>(buffer);
    if (unlikely(UserAndGroupCount == 0))
        // No users or groups, what?
        return;

    /*
     * header->UserAndGroups points to the first element of an array of _SID_AND_ATTRIBUTES,
     * with header->UserAndGroupCount elements. Each element is sizeof(_SID_AND_ATTRIBUTES). The
     * first element is the User, the rest are Groups
     */
    const auto pUserAndGroups = gva.create(token->UserAndGroups.get<PtrType>(buffer));
    user_.emplace(pUserAndGroups);
    for (size_t i = 1; i < UserAndGroupCount; ++i) {
        const auto pSidAndAttributes = pUserAndGroups + (i * sid_and_attributes->size());
        groups_.emplace_back(std::make_shared<SID_AND_ATTRIBUTES_IMPL<PtrType>>(pSidAndAttributes));
    }

    const auto pPrimaryGroup = gva.create(token->PrimaryGroup.get<PtrType>(buffer));
    if (pPrimaryGroup)
        primary_group_.emplace(pPrimaryGroup);
}

template <typename PtrType>
TOKEN_IMPL<PtrType>::TOKEN_IMPL(const NtKernelImpl<PtrType>& kernel, const GuestVirtualAddress& gva)
    : OBJECT_IMPL<PtrType, TOKEN>(kernel, gva, ObjectType::Token), kernel_(kernel) {

    init(kernel, gva);
}

template <typename PtrType>
TOKEN_IMPL<PtrType>::TOKEN_IMPL(const NtKernelImpl<PtrType>& kernel,
                                std::unique_ptr<OBJECT_HEADER_IMPL<PtrType>>&& object_header)
    : OBJECT_IMPL<PtrType, TOKEN>(kernel, std::move(object_header), ObjectType::Token),
      kernel_(kernel) {

    init(kernel, OBJECT_IMPL<PtrType, TOKEN>::address());
}

std::shared_ptr<TOKEN> TOKEN::make_shared(const NtKernel& kernel, const GuestVirtualAddress& gva) {
    if (kernel.x64())
        return std::make_shared<TOKEN_IMPL<uint64_t>>(
            static_cast<const NtKernelImpl<uint64_t>&>(kernel), gva);
    else
        return std::make_shared<TOKEN_IMPL<uint32_t>>(
            static_cast<const NtKernelImpl<uint32_t>&>(kernel), gva);
}

std::shared_ptr<TOKEN> TOKEN::make_shared(const NtKernel& kernel,
                                          std::unique_ptr<OBJECT_HEADER>&& object_header) {
    if (kernel.x64()) {
        std::unique_ptr<OBJECT_HEADER_IMPL<uint64_t>> object_header_impl;
        object_header_impl.reset(
            static_cast<OBJECT_HEADER_IMPL<uint64_t>*>(object_header.release()));
        return std::make_shared<TOKEN_IMPL<uint64_t>>(
            static_cast<const NtKernelImpl<uint64_t>&>(kernel), std::move(object_header_impl));
    } else {
        std::unique_ptr<OBJECT_HEADER_IMPL<uint32_t>> object_header_impl;
        object_header_impl.reset(
            static_cast<OBJECT_HEADER_IMPL<uint32_t>*>(object_header.release()));
        return std::make_shared<TOKEN_IMPL<uint32_t>>(
            static_cast<const NtKernelImpl<uint32_t>&>(kernel), std::move(object_header_impl));
    }
}

template class TOKEN_IMPL<uint32_t>;
template class TOKEN_IMPL<uint64_t>;

} /* namespace nt */
} /* namespace windows */
} /* namespace introvirt */
