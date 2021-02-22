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

#include <introvirt/windows/kernel/nt/types/objects/OBJECT_DIRECTORY.hh>

#include "windows/kernel/nt/structs/structs.hh"

#include <introvirt/core/memory/guest_ptr.hh>
#include <introvirt/fwd.hh>

namespace introvirt {
namespace windows {
namespace nt {

template <typename PtrType>
class OBJECT_DIRECTORY_IMPL final : public OBJECT_IMPL<PtrType, OBJECT_DIRECTORY> {
  public:
    const std::vector<std::shared_ptr<OBJECT>>& objects() const override;
    std::vector<std::shared_ptr<OBJECT>>& objects() override;

    OBJECT_DIRECTORY_IMPL(const NtKernelImpl<PtrType>& kernel, const GuestVirtualAddress& gva);
    OBJECT_DIRECTORY_IMPL(const NtKernelImpl<PtrType>& kernel,
                          std::unique_ptr<OBJECT_HEADER_IMPL<PtrType>>&& objHeader);

  private:
    void init(const NtKernelImpl<PtrType>& kernel, const GuestVirtualAddress& gva);

  private:
    guest_ptr<char[]> buffer_;
    std::vector<std::shared_ptr<OBJECT>> objects_;
};

} // namespace nt
} // namespace windows
} // namespace introvirt