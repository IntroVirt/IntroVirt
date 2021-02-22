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
#include "windows/kernel/nt/types/UNICODE_STRING_IMPL.hh"

#include <introvirt/core/memory/guest_ptr.hh>
#include <introvirt/fwd.hh>
#include <introvirt/windows/kernel/nt/types/objects/OBJECT_TYPE.hh>

#include <optional>

namespace introvirt {
namespace windows {
namespace nt {

template <typename PtrType>
class OBJECT_TYPE_IMPL final : public OBJECT_IMPL<PtrType, OBJECT_TYPE> {
  public:
    const std::string& Name() const override;
    uint32_t TotalNumberOfObjects() const override;
    uint32_t TotalNumberOfHandles() const override;
    uint32_t HighWaterNumberOfObjects() const override;
    uint32_t HighWaterNumberOfHandles() const override;
    uint32_t Key() const override;
    uint8_t Index() const override;

    OBJECT_TYPE_IMPL(const NtKernelImpl<PtrType>& kernel, const GuestVirtualAddress& gva);
    OBJECT_TYPE_IMPL(const NtKernelImpl<PtrType>& kernel,
                     std::unique_ptr<OBJECT_HEADER_IMPL<PtrType>>&& object_header);

  private:
    const NtKernelImpl<PtrType>& kernel_;
    const structs::OBJECT_TYPE* offsets_;

    guest_ptr<char[]> buffer_;

    mutable std::recursive_mutex mtx_;
    mutable std::optional<UNICODE_STRING_IMPL<PtrType>> Name_;
};

} // namespace nt
} // namespace windows
} // namespace introvirt