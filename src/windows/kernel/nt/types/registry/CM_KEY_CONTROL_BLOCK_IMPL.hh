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
#include <introvirt/fwd.hh>
#include <introvirt/windows/kernel/nt/types/registry/CM_KEY_CONTROL_BLOCK.hh>

#include <mutex>
#include <optional>

namespace introvirt {
namespace windows {
namespace nt {

template <typename PtrType>
class HIVE_IMPL;

template <typename PtrType>
class NtKernelImpl;

template <typename PtrType>
class CM_KEY_CONTROL_BLOCK_IMPL final : public CM_KEY_CONTROL_BLOCK {
  public:
    const CM_KEY_CONTROL_BLOCK* ParentKcb() const override;

    const std::string& Name() const override;

    const HIVE* KeyHive() const override;

    const CM_KEY_CONTROL_BLOCK::KeyFlags Flags() const override;

    const CM_KEY_CONTROL_BLOCK::KeyExtFlags ExtFlags() const override;

    GuestVirtualAddress address() const override;

    CM_KEY_CONTROL_BLOCK_IMPL(const NtKernelImpl<PtrType>& kernel, const GuestVirtualAddress& gva);
    ~CM_KEY_CONTROL_BLOCK_IMPL() override;

  private:
    const NtKernelImpl<PtrType>& kernel_;
    const GuestVirtualAddress gva_;

    const structs::CM_KEY_CONTROL_BLOCK* cm_key_control_block;
    const structs::CM_NAME_CONTROL_BLOCK* cm_name_control_block;

    guest_ptr<char[]> cm_key_control_block_buffer;
    mutable guest_ptr<char[]> cm_name_control_block_buffer;

    mutable std::recursive_mutex mtx_;

    mutable std::unique_ptr<HIVE_IMPL<PtrType>> KeyHive_;
    mutable std::unique_ptr<CM_KEY_CONTROL_BLOCK_IMPL<PtrType>> parentKCB;

    mutable std::string name;
};

} // namespace nt
} // namespace windows
} // namespace introvirt