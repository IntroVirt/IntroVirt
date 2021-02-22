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
#include "TOKEN_GROUPS_IMPL.hh"

#include <introvirt/core/exception/BufferTooSmallException.hh>
#include <introvirt/util/compiler.hh>

#include <log4cxx/logger.h>

#include <cassert>

namespace introvirt {
namespace windows {
namespace nt {

static log4cxx::LoggerPtr logger(log4cxx::Logger::getLogger(
    "introvirt.win.kernel.nt.syscall.types.token_information.TOKEN_GROUPS"));

template <typename PtrType>
void TOKEN_GROUPS_IMPL<PtrType>::write(std::ostream& os, const std::string& linePrefix) const {
    TOKEN_INFORMATION_IMPL_TYPE::write(os, linePrefix);
    for (const SID_AND_ATTRIBUTES& sid_and_attributes : *this) {
        const SID* sid = sid_and_attributes.Sid();
        if (sid != nullptr) {
            os << linePrefix << "SID: " << *sid << '\n';
            os << linePrefix << "\tAttributes: " << sid_and_attributes.Attributes() << '\n';
        }
    }
}

template <typename PtrType>
Json::Value TOKEN_GROUPS_IMPL<PtrType>::json() const {
    Json::Value groupsJSON;

    for (const auto& sid_and_attributes : *this) {
        groupsJSON.append(sid_and_attributes.json());
    }

    Json::Value result = TOKEN_INFORMATION_IMPL_TYPE::json();
    result["Groups"] = std::move(groupsJSON);
    return result;
}

template <typename PtrType>
TOKEN_GROUPS_IMPL<PtrType>::TOKEN_GROUPS_IMPL(const GuestVirtualAddress& gva, uint32_t buffer_size)
    : array_iterable_type(gva, gva + offsetof(structs::_TOKEN_GROUPS<PtrType>, Groups),
                          TOKEN_INFORMATION_CLASS::TokenGroups, gva,
                          buffer_size - offsetof(structs::_TOKEN_GROUPS<PtrType>, Groups)) {}

template class TOKEN_GROUPS_IMPL<uint32_t>;
template class TOKEN_GROUPS_IMPL<uint64_t>;

} // namespace nt
} // namespace windows
} // namespace introvirt