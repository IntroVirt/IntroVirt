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
#include "TOKEN_OWNER_IMPL.hh"
#include "windows/kernel/nt/types/SID_IMPL.hh"

#include <introvirt/core/exception/BufferTooSmallException.hh>
#include <introvirt/util/compiler.hh>

namespace introvirt {
namespace windows {
namespace nt {

template <typename PtrType>
guest_ptr<void> TOKEN_OWNER_IMPL<PtrType>::OwnerPtr() const {
    return this->ptr_->Owner.get(this->ptr_);
}

template <typename PtrType>
void TOKEN_OWNER_IMPL<PtrType>::OwnerPtr(const guest_ptr<void>& ptr) {
    this->ptr_->Owner.set(ptr);
    Owner_.reset();
}

template <typename PtrType>
SID* TOKEN_OWNER_IMPL<PtrType>::Owner() {
    const auto* const_this = this;
    return const_cast<SID*>(const_this->Owner());
}

template <typename PtrType>
const SID* TOKEN_OWNER_IMPL<PtrType>::Owner() const {
    {
        std::lock_guard lock(owner_initialized_);
        if (!Owner_)
            Owner_.emplace(this->ptr_->Owner.get(this->ptr_));
    }
    if (Owner_)
        return (&*Owner_);
    else
        return nullptr;
}

template <typename PtrType>
void TOKEN_OWNER_IMPL<PtrType>::write(std::ostream& os, const std::string& linePrefix) const {
    TOKEN_OWNER_IMPL_BASE::write(os, linePrefix);
    os << linePrefix << "SID: ";
    if (Owner())
        os << *Owner() << '\n';
    else
        os << "null\n";
}

template <typename PtrType>
Json::Value TOKEN_OWNER_IMPL<PtrType>::json() const {
    Json::Value result = TOKEN_OWNER_IMPL_BASE::json();
    result["Owner"] = Owner()->json();
    return result;
}

template <typename PtrType>
TOKEN_OWNER_IMPL<PtrType>::TOKEN_OWNER_IMPL(const guest_ptr<void>& ptr, uint32_t buffer_size)
    : TOKEN_OWNER_IMPL_BASE(TOKEN_INFORMATION_CLASS::TokenOwner, ptr, buffer_size) {}

template class TOKEN_OWNER_IMPL<uint32_t>;
template class TOKEN_OWNER_IMPL<uint64_t>;

} // namespace nt
} // namespace windows
} // namespace introvirt