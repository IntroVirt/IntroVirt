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
#include "windows/kernel/nt/types/SEGMENT_IMPL.hh"
#include "windows/kernel/nt/types/objects/FILE_OBJECT_IMPL.hh"

#include <introvirt/core/memory/guest_ptr.hh>
#include <introvirt/windows/kernel/nt/types/CONTROL_AREA.hh>
#include <introvirt/windows/kernel/nt/types/SEGMENT.hh>

#include <optional>

namespace introvirt {
namespace windows {
namespace nt {

template <typename PtrType>
class NtKernelImpl;

template <typename PtrType>
class CONTROL_AREA_IMPL final : public CONTROL_AREA {
  public:
    const SEGMENT* Segment() const override;
    const FILE_OBJECT* FileObject() const override;

    CONTROL_AREA_IMPL(const NtKernelImpl<PtrType>& kernel, const GuestVirtualAddress& gva);

  private:
    const NtKernelImpl<PtrType>& kernel_;
    const GuestVirtualAddress gva_;

    const structs::CONTROL_AREA* control_area_;
    guest_ptr<char[]> buffer_;

    mutable std::optional<SEGMENT_IMPL<PtrType>> Segment_;
    mutable std::optional<FILE_OBJECT_IMPL<PtrType>> FileObject_;
};

} // namespace nt
} // namespace windows
} // namespace introvirt