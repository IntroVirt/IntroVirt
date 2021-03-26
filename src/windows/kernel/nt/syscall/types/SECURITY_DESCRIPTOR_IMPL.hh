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

#include "windows/kernel/nt/structs/structs.hh"
#include "windows/kernel/nt/types/SID_IMPL.hh"

#include <introvirt/core/memory/guest_ptr.hh>
#include <introvirt/windows/kernel/nt/syscall/types/SECURITY_DESCRIPTOR.hh>

#include <mutex>
#include <optional>

namespace introvirt {
namespace windows {
namespace nt {

namespace structs {

template <typename PtrType>
struct _SECURITY_DESCRIPTOR {
    uint8_t Revision;
    uint8_t Sbz1;
    SECURITY_DESCRIPTOR_CONTROL Control;
    guest_member_ptr<_SID, PtrType> Owner;
    guest_member_ptr<_SID, PtrType> Group;
    PtrType Sacl; /* ACL */
    PtrType Dacl; /* ACL */
};

static_assert(sizeof(_SECURITY_DESCRIPTOR<uint32_t>) == 0x14);
static_assert(sizeof(_SECURITY_DESCRIPTOR<uint64_t>) == 0x28);

} // namespace structs

template <typename PtrType>
class SECURITY_DESCRIPTOR_IMPL final : public SECURITY_DESCRIPTOR {
    using _SECURITY_DESCRIPTOR = structs::_SECURITY_DESCRIPTOR<PtrType>;

  public:
    uint8_t Revision() const override { return ptr_->Revision; }
    void Revision(uint8_t Revision) override { ptr_->Revision = Revision; }

    uint8_t Sbz1() const override { return ptr_->Sbz1; }
    void Sbz1(uint8_t Sbz1) override { ptr_->Sbz1 = Sbz1; }

    SECURITY_DESCRIPTOR_CONTROL Control() const override { return ptr_->Control; }
    void Control(SECURITY_DESCRIPTOR_CONTROL Control) override { ptr_->Control = Control; }

    SID* Owner() override {
        {
            std::lock_guard lock(OwnerInit_);
            if (!Owner_) {
                if (ptr_->Owner)
                    Owner_.emplace(ptr_->Owner.get(ptr_));
            }
        }

        if (Owner_.has_value())
            return &(*Owner_);

        return nullptr;
    }

    SID* Group() override {
        {
            std::lock_guard lock(OwnerInit_);
            if (!Group_) {
                if (ptr_->Group)
                    Group_.emplace(ptr_->Group.get(ptr_));
            }
        }

        if (Group_.has_value())
            return &(*Group_);

        return nullptr;
    }

    // TODO(pape): Getters for ACLs

    guest_ptr<void> ptr() const override { return ptr_; }

    SECURITY_DESCRIPTOR_IMPL(const guest_ptr<void>& ptr) : ptr_(ptr) {}
    SECURITY_DESCRIPTOR_IMPL(guest_ptr<_SECURITY_DESCRIPTOR>&& ptr) : ptr_(std::move(ptr)) {}

  private:
    guest_ptr<structs::_SECURITY_DESCRIPTOR<PtrType>> ptr_;

    std::mutex OwnerInit_;
    std::optional<SID_IMPL> Owner_;

    std::mutex GroupInit_;
    std::optional<SID_IMPL> Group_;
};

} // namespace nt
} // namespace windows
} // namespace introvirt