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
#include <introvirt/windows/common/WStr.hh>
#include <introvirt/windows/kernel/nt/types/registry/HBASE_BLOCK.hh>

#include <optional>

namespace introvirt {
namespace windows {
namespace nt {

template <typename PtrType>
class NtKernelImpl;

template <typename PtrType>
class HBASE_BLOCK_IMPL final : public HBASE_BLOCK {
  public:
    const int64_t TimeStamp() const override;
    const std::string& FileName() const override;
    uint32_t RootCell() const override;
    uint32_t Length() const override;
    GuestVirtualAddress address() const override;

    HBASE_BLOCK_IMPL(const NtKernelImpl<PtrType>& kernel, const GuestVirtualAddress& gva);
    ~HBASE_BLOCK_IMPL() override;

  private:
    const NtKernelImpl<PtrType>& kernel_;
    const GuestVirtualAddress gva_;
    const structs::HBASE_BLOCK* hbase_block;
    guest_ptr<char[]> hbase_block_buffer_;
    mutable std::optional<WStr> FileName_; // TODO: Use WstrImpl
};

} // namespace nt
} // namespace windows
} // namespace introvirt