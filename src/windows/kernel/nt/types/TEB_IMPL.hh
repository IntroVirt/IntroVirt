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

#include "CLIENT_ID_IMPL.hh"
#include "NT_TIB_IMPL.hh"
#include "windows/kernel/nt/structs/structs.hh"

#include <introvirt/core/memory/guest_ptr.hh>
#include <introvirt/windows/kernel/nt/types/TEB.hh>

#include <optional>

namespace introvirt {
namespace windows {
namespace nt {

template <typename PtrType>
class NtKernelImpl;

template <typename PtrType>
class TEB_IMPL final : public TEB {
  public:
    const NT_TIB& NtTib() const override;
    const CLIENT_ID& ClientId() const override;

    WinError LastErrorValue() const override;
    void LastErrorValue(WinError LastErrorValue) override;

    NTSTATUS LastStatusValue() const override;
    void LastStatusValue(NTSTATUS value) override;

    GuestVirtualAddress address() const override;

    TEB_IMPL(const NtKernelImpl<PtrType>& kernel, const GuestVirtualAddress& gva);

  private:
    const NtKernelImpl<PtrType>& kernel_;
    const GuestVirtualAddress gva_;

    const structs::TEB* teb_;
    guest_ptr<char[]> buffer_;

    mutable std::optional<NT_TIB_IMPL<PtrType>> NtTib_;
    mutable std::optional<CLIENT_ID_IMPL<PtrType>> ClientId_;
};

} // namespace nt
} // namespace windows
} // namespace introvirt