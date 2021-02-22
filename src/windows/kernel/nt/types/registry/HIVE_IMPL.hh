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

#include "HBASE_BLOCK_IMPL.hh"
#include "windows/kernel/nt/structs/structs.hh"

#include <introvirt/core/memory/guest_ptr.hh>
#include <introvirt/fwd.hh>
#include <introvirt/windows/kernel/nt/types/registry/CM_KEY_NODE.hh>
#include <introvirt/windows/kernel/nt/types/registry/HIVE.hh>

#include <memory>
#include <optional>

namespace introvirt {
namespace windows {
namespace nt {

template <typename PtrType>
class NtKernelImpl;

template <typename PtrType>
class CM_KEY_NODE_IMPL;

template <typename PtrType>
class HIVE_IMPL final : public HIVE {
  public:
    const std::string& FileFullPath() const override;
    const std::string& FileUserName() const override;
    const std::string& HiveRootPath() const override;
    const HBASE_BLOCK& BaseBlock() const override;
    const CM_KEY_NODE* RootKeyNode() const override;
    const CM_KEY_NODE* KeyNode(uint32_t KeyIndex) const override;
    GuestVirtualAddress CellAddress(uint32_t KeyIndex) const override;
    const HIVE* PreviousHive() const override;
    const HIVE* NextHive() const override;
    uint32_t HiveFlags() const override;
    GuestVirtualAddress address() const override;

    HIVE_IMPL(const NtKernelImpl<PtrType>& kernel, const GuestVirtualAddress& gva);
    ~HIVE_IMPL() override;

  private:
    GuestVirtualAddress getBlockAddress(GuestVirtualAddress pEntry) const;

    const NtKernelImpl<PtrType>& kernel_;
    const GuestVirtualAddress gva_;

    const structs::CMHIVE* cmhive_;
    const structs::DUAL* dual_;
    const structs::HMAP_ENTRY* hmap_entry_;

    guest_ptr<char[]> cmhive_buffer_;

    mutable std::unordered_map<uint32_t, std::unique_ptr<CM_KEY_NODE_IMPL<PtrType>>>
        KeyIndexNodeMap_;

    mutable std::optional<HBASE_BLOCK_IMPL<PtrType>> BaseBlock_;
    mutable std::string FileFullPath_;
    mutable std::string FileUserName_;
    mutable std::string HiveRootPath_;

    mutable std::unique_ptr<HIVE_IMPL<PtrType>> PreviousHive_;
    mutable std::unique_ptr<HIVE_IMPL<PtrType>> NextHive_;
};

} // namespace nt
} // namespace windows
} // namespace introvirt