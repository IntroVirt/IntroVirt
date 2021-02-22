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

#include "OBJECT_IMPL.hh"
#include "windows/kernel/nt/structs/structs.hh"
#include "windows/kernel/nt/types/registry/CM_KEY_CONTROL_BLOCK_IMPL.hh"

#include <introvirt/core/memory/guest_ptr.hh>
#include <introvirt/fwd.hh>
#include <introvirt/windows/kernel/nt/types/objects/CM_KEY_BODY.hh>

#include <mutex>
#include <optional>

namespace introvirt {
namespace windows {
namespace nt {

template <typename PtrType>
class CM_KEY_BODY_IMPL final : public OBJECT_IMPL<PtrType, CM_KEY_BODY> {
  public:
    const CM_KEY_CONTROL_BLOCK& KeyControlBlock() const override;
    uint64_t ProcessID() const override;
    const std::string& full_key_path() const override;

    CM_KEY_BODY_IMPL(const NtKernelImpl<PtrType>& kernel, const GuestVirtualAddress& gva);
    CM_KEY_BODY_IMPL(const NtKernelImpl<PtrType>& kernel,
                     std::unique_ptr<OBJECT_HEADER_IMPL<PtrType>>&& object_header);

  private:
    const NtKernelImpl<PtrType>& kernel_;
    const structs::CM_KEY_BODY* offsets_;

    guest_ptr<char[]> buffer_;

    mutable std::recursive_mutex mtx_;
    mutable std::unique_ptr<CM_KEY_CONTROL_BLOCK_IMPL<PtrType>> KeyControlBlock_;
    mutable std::string full_path_;
};

} // namespace nt
} // namespace windows
} // namespace introvirt
