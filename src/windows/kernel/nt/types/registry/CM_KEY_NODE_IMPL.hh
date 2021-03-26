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

#include "CM_KEY_VALUE_IMPL.hh"
#include "HIVE_IMPL.hh"
#include "windows/kernel/nt/structs/structs.hh"

#include <introvirt/fwd.hh>
#include <introvirt/windows/kernel/nt/types/registry/CM_KEY_NODE.hh>

namespace introvirt {
namespace windows {
namespace nt {

template <typename PtrType>
class NtKernelImpl;

template <typename PtrType>
class CM_KEY_NODE_IMPL final : public CM_KEY_NODE {
  public:
    const std::string& Name() const override;
    uint16_t Flags() const override;
    const std::vector<std::unique_ptr<CM_KEY_NODE>>& StableSubKeys() const override;
    const std::vector<std::unique_ptr<CM_KEY_NODE>>& VolatileSubKeys() const override;
    const std::vector<std::unique_ptr<CM_KEY_VALUE>>& Values() const override;
    guest_ptr<void> ptr() const override { return cm_key_node_buffer_; }

    CM_KEY_NODE_IMPL(const NtKernelImpl<PtrType>& kernel, const HIVE_IMPL<PtrType>& hive,
                     const guest_ptr<void>& ptr);

    ~CM_KEY_NODE_IMPL() override;

  private:
    void addLfLhList(const guest_ptr<void>& pList,
                     std::vector<std::unique_ptr<CM_KEY_NODE>>& output) const;
    void addLiList(const guest_ptr<void>& pList,
                   std::vector<std::unique_ptr<CM_KEY_NODE>>& output) const;
    void addRiList(const guest_ptr<void>& pList,
                   std::vector<std::unique_ptr<CM_KEY_NODE>>& output) const;
    void getSubKeys(unsigned int listIndex,
                    std::vector<std::unique_ptr<CM_KEY_NODE>>& output) const;

  private:
    const NtKernelImpl<PtrType>& kernel_;
    const HIVE_IMPL<PtrType>& hive_;
    guest_ptr<void> ptr_;

    const structs::CM_KEY_NODE* cm_key_node_;
    const structs::CM_KEY_INDEX* cm_key_index_;

    guest_ptr<char[]> cm_key_node_buffer_;

    mutable std::vector<std::unique_ptr<CM_KEY_NODE>> stableSubKeys_;
    mutable std::vector<std::unique_ptr<CM_KEY_NODE>> volatileSubKeys_;
    mutable std::vector<std::unique_ptr<CM_KEY_VALUE>> Values_;

    mutable std::string Name_;
};

} // namespace nt
} // namespace windows
} // namespace introvirt