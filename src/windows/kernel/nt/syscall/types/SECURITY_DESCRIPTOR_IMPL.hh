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
    PtrType Owner; /* SID */
    PtrType Group; /* SID */
    PtrType Sacl;  /* ACL */
    PtrType Dacl;  /* ACL */
};

static_assert(sizeof(_SECURITY_DESCRIPTOR<uint32_t>) == 0x14);
static_assert(sizeof(_SECURITY_DESCRIPTOR<uint64_t>) == 0x28);

} // namespace structs

template <typename PtrType>
class SECURITY_DESCRIPTOR_IMPL final : public SECURITY_DESCRIPTOR {
  public:
    uint8_t Revision() const override;
    uint8_t Sbz1() const override;
    SECURITY_DESCRIPTOR_CONTROL Control() const override;

    SID* Owner() override;
    const SID* Owner() const override;
    SID* Group() override;
    const SID* Group() const override;
    // TODO(pape): Getters for ACLs

    void Revision(uint8_t Revision) override;
    void Sbz1(uint8_t Sbz1) override;
    void Control(SECURITY_DESCRIPTOR_CONTROL Control) override;

    GuestVirtualAddress address() const override;

    SECURITY_DESCRIPTOR_IMPL(const GuestVirtualAddress& gva);

  private:
    GuestVirtualAddress OwnerPtr() const;
    GuestVirtualAddress GroupPtr() const;
    GuestVirtualAddress SaclPtr() const;
    GuestVirtualAddress DaclPtr() const;

  private:
    const GuestVirtualAddress gva_;
    guest_ptr<structs::_SECURITY_DESCRIPTOR<PtrType>> header_;

    std::mutex OwnerInit_;
    std::optional<SID_IMPL> Owner_;

    std::mutex GroupInit_;
    std::optional<SID_IMPL> Group_;
};

} // namespace nt
} // namespace windows
} // namespace introvirt