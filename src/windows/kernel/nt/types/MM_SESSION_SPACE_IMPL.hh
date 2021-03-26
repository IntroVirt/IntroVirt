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

#include <introvirt/windows/kernel/nt/types/MM_SESSION_SPACE.hh>

namespace introvirt {
namespace windows {
namespace nt {

template <typename PtrType>
class NtKernelImpl;

template <typename PtrType>
class MM_SESSION_SPACE_IMPL final : public MM_SESSION_SPACE {
  public:
    guest_ptr<void> ptr() const override { return ptr_; }

    uint32_t SessionID() const override;

    std::vector<std::shared_ptr<const PROCESS>> process_list() const override;

    MM_SESSION_SPACE_IMPL(const NtKernelImpl<PtrType>& kernel, const guest_ptr<void>& ptr);

  private:
    uint16_t SessionProcessLinksOffset() const;
    guest_ptr<void> SessionProcListHeadAddress() const;

  private:
    const NtKernel& kernel_;
    const guest_ptr<void> ptr_;
    const structs::MM_SESSION_SPACE* mm_session_space;
    const structs::EPROCESS* eprocess;
    guest_ptr<char[]> buffer;
};

} // namespace nt
} // namespace windows
} // namespace introvirt