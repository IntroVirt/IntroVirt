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
#include "TOKEN_USER_IMPL.hh"

#include <introvirt/core/exception/BufferTooSmallException.hh>
#include <introvirt/util/compiler.hh>

namespace introvirt {
namespace windows {
namespace nt {

template <typename PtrType>
SID_AND_ATTRIBUTES& TOKEN_USER_IMPL<PtrType>::User() {
    const auto* const_this = this;
    return const_cast<SID_AND_ATTRIBUTES&>(const_this->User());
}

template <typename PtrType>
const SID_AND_ATTRIBUTES& TOKEN_USER_IMPL<PtrType>::User() const {
    {
        std::lock_guard lock(UserInit_);
        if (!User_)
            User_.emplace(this->gva_);
    }
    return *User_;
}

template <typename PtrType>
void TOKEN_USER_IMPL<PtrType>::write(std::ostream& os, const std::string& linePrefix) const {
    TOKEN_USER_IMPL_BASE::write(os, linePrefix);
    os << linePrefix << "SID: " << *(User().Sid()) << '\n';
    os << linePrefix << "Attributes: " << User().Attributes() << '\n';
}

template <typename PtrType>
Json::Value TOKEN_USER_IMPL<PtrType>::json() const {
    Json::Value result = TOKEN_USER_IMPL_BASE::json();
    result["User"] = User().json();
    return result;
}

template <typename PtrType>
TOKEN_USER_IMPL<PtrType>::TOKEN_USER_IMPL(const GuestVirtualAddress& gva, uint32_t buffer_size)
    : TOKEN_USER_IMPL_BASE(TOKEN_INFORMATION_CLASS::TokenUser, gva, buffer_size) {}

template class TOKEN_USER_IMPL<uint32_t>;
template class TOKEN_USER_IMPL<uint64_t>;

} // namespace nt
} // namespace windows
} // namespace introvirt