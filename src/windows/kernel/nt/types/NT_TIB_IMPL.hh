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

#include <introvirt/core/memory/guest_ptr.hh>
#include <introvirt/windows/kernel/nt/types/NT_TIB.hh>

namespace introvirt {
namespace windows {
namespace nt {

template <typename PtrType>
class NtKernelImpl;

template <typename PtrType>
class NT_TIB_IMPL final : public NT_TIB {
  public:
    GuestVirtualAddress StackLimit() const override;
    GuestVirtualAddress StackBase() const override;

    NT_TIB_IMPL(const NtKernelImpl<PtrType>& kernel, const GuestVirtualAddress& gva);

  private:
    const GuestVirtualAddress gva_;
    const structs::NT_TIB* nt_tib;
    guest_ptr<char[]> buffer;
};

} // namespace nt
} // namespace windows
} // namespace introvirt