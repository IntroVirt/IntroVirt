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
#include "SECURITY_DESCRIPTOR_IMPL.hh"

#include <introvirt/windows/kernel/nt/NtKernel.hh>

namespace introvirt {
namespace windows {
namespace nt {

template <typename PtrType>
SID* SECURITY_DESCRIPTOR_IMPL<PtrType>::Owner() {
    {
        std::lock_guard lock(OwnerInit_);
        if (!Owner_) {
            GuestVirtualAddress ptr = OwnerPtr();
            if (ptr)
                Owner_.emplace(ptr);
        }
    }

    if (Owner_.has_value())
        return &(*Owner_);

    return nullptr;
}

template <typename PtrType>
const SID* SECURITY_DESCRIPTOR_IMPL<PtrType>::Owner() const {
    return const_cast<SECURITY_DESCRIPTOR_IMPL<PtrType>*>(this)->Owner();
}

template <typename PtrType>
SID* SECURITY_DESCRIPTOR_IMPL<PtrType>::Group() {
    {
        std::lock_guard lock(GroupInit_);
        if (!Group_) {
            GuestVirtualAddress ptr = GroupPtr();
            if (ptr)
                Group_.emplace(ptr);
        }
    }

    if (Group_.has_value())
        return &(*Group_);

    return nullptr;
}

template <typename PtrType>
const SID* SECURITY_DESCRIPTOR_IMPL<PtrType>::Group() const {
    return const_cast<SECURITY_DESCRIPTOR_IMPL<PtrType>*>(this)->Group();
}

template <typename PtrType>
uint8_t SECURITY_DESCRIPTOR_IMPL<PtrType>::Revision() const {
    return header_->Revision;
}

template <typename PtrType>
uint8_t SECURITY_DESCRIPTOR_IMPL<PtrType>::Sbz1() const {
    return header_->Sbz1;
}

template <typename PtrType>
SECURITY_DESCRIPTOR_CONTROL SECURITY_DESCRIPTOR_IMPL<PtrType>::Control() const {
    return header_->Control;
}

template <typename PtrType>
void SECURITY_DESCRIPTOR_IMPL<PtrType>::Revision(uint8_t Revision) {
    header_->Revision = Revision;
}

template <typename PtrType>
void SECURITY_DESCRIPTOR_IMPL<PtrType>::Sbz1(uint8_t Sbz1) {
    header_->Sbz1 = Sbz1;
}

template <typename PtrType>
void SECURITY_DESCRIPTOR_IMPL<PtrType>::Control(SECURITY_DESCRIPTOR_CONTROL Control) {
    header_->Control = Control;
}

template <typename PtrType>
GuestVirtualAddress SECURITY_DESCRIPTOR_IMPL<PtrType>::OwnerPtr() const {
    return gva_.create(header_->Owner);
}

template <typename PtrType>
GuestVirtualAddress SECURITY_DESCRIPTOR_IMPL<PtrType>::GroupPtr() const {
    return gva_.create(header_->Group);
}

template <typename PtrType>
GuestVirtualAddress SECURITY_DESCRIPTOR_IMPL<PtrType>::SaclPtr() const {
    return gva_.create(header_->Sacl);
}

template <typename PtrType>
GuestVirtualAddress SECURITY_DESCRIPTOR_IMPL<PtrType>::DaclPtr() const {
    return gva_.create(header_->Dacl);
}

template <typename PtrType>
GuestVirtualAddress SECURITY_DESCRIPTOR_IMPL<PtrType>::address() const {
    return gva_;
}

template <typename PtrType>
SECURITY_DESCRIPTOR_IMPL<PtrType>::SECURITY_DESCRIPTOR_IMPL(const GuestVirtualAddress& gva)
    : gva_(gva), header_(gva) {}

template class SECURITY_DESCRIPTOR_IMPL<uint32_t>;
template class SECURITY_DESCRIPTOR_IMPL<uint64_t>;

} // namespace nt
} // namespace windows
} // namespace introvirt
