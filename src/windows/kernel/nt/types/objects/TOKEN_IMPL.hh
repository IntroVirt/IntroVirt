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

#include "DISPATCHER_OBJECT_IMPL.hh"
#include "windows/kernel/nt/structs/structs.hh"
#include "windows/kernel/nt/types/SID_AND_ATTRIBUTES_IMPL.hh"
#include "windows/kernel/nt/types/SID_IMPL.hh"

#include <introvirt/core/memory/guest_ptr.hh>
#include <introvirt/fwd.hh>
#include <introvirt/windows/kernel/nt/types/objects/TOKEN.hh>

#include <optional>

namespace introvirt {
namespace windows {
namespace nt {

template <typename PtrType>
class TOKEN_IMPL final : public OBJECT_IMPL<PtrType, TOKEN> {
  public:
    std::vector<std::shared_ptr<SID_AND_ATTRIBUTES>> Groups() override;
    std::vector<std::shared_ptr<const SID_AND_ATTRIBUTES>> Groups() const override;

    const SID* User() const override;
    const SID* PrimaryGroup() const override;

    uint64_t PrivilegesPresent() const override;
    void PrivilegesPresent(uint64_t Privileges) override;

    uint64_t PrivilegesEnabled() const override;
    void PrivilegesEnabled(uint64_t Privileges) override;

    TOKEN_IMPL(const NtKernelImpl<PtrType>& kernel, const GuestVirtualAddress& gva);
    TOKEN_IMPL(const NtKernelImpl<PtrType>& kernel,
               std::unique_ptr<OBJECT_HEADER_IMPL<PtrType>>&& object_header);

  private:
    void init(const NtKernelImpl<PtrType>& kernel, const GuestVirtualAddress& gva);

    const NtKernelImpl<PtrType>& kernel_;
    const structs::TOKEN* token;

    guest_ptr<char[]> buffer;

    std::optional<SID_AND_ATTRIBUTES_IMPL<PtrType>> user_;
    std::optional<SID_IMPL> primary_group_;
    std::vector<std::shared_ptr<SID_AND_ATTRIBUTES>> groups_;
};

} // namespace nt
} // namespace windows
} // namespace introvirt