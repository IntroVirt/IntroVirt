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

#include <introvirt/windows/kernel/nt/types/SEGMENT.hh>

#include <optional>

namespace introvirt {
namespace windows {
namespace nt {

template <typename PtrType>
class CONTROL_AREA_IMPL;

template <typename PtrType>
class NtKernelImpl;

template <typename PtrType>
class SEGMENT_IMPL final : public SEGMENT {
  public:
    const CONTROL_AREA* ControlArea() const override;
    uint64_t FirstMappedVa() const override;
    uint64_t SizeOfSegment() const override;

    SEGMENT_IMPL(const NtKernelImpl<PtrType>& kernel, const GuestVirtualAddress& gva,
                 const CONTROL_AREA_IMPL<PtrType>* control_area = nullptr);

  private:
    const NtKernelImpl<PtrType>& kernel_;
    const GuestVirtualAddress gva_;

    const structs::SEGMENT* segment_;
    guest_ptr<char[]> buffer_;

    mutable std::unique_ptr<CONTROL_AREA_IMPL<PtrType>> allocated_control_area_;
    mutable const CONTROL_AREA* control_area_;
};

} // namespace nt
} // namespace windows
} // namespace introvirt