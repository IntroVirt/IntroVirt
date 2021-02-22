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

#include "FILE_OBJECT_IMPL.hh"
#include "OBJECT_IMPL.hh"
#include "windows/kernel/nt/structs/structs.hh"
#include "windows/kernel/nt/types/CONTROL_AREA_IMPL.hh"

#include <introvirt/core/memory/guest_ptr.hh>
#include <introvirt/fwd.hh>
#include <introvirt/windows/kernel/nt/types/CONTROL_AREA.hh>
#include <introvirt/windows/kernel/nt/types/objects/SECTION.hh>

#include <optional>

namespace introvirt {
namespace windows {
namespace nt {

template <typename PtrType>
class SECTION_OBJECT_IMPL final : public OBJECT_IMPL<PtrType, SECTION> {
  public:
    uint64_t StartingVpn() const override;
    uint64_t EndingVpn() const override;

    GuestVirtualAddress StartingVa() const override;
    GuestVirtualAddress EndingVa() const override;

    uint64_t SizeOfSection() const override;

    const CONTROL_AREA* ControlArea() const override;
    const FILE_OBJECT* FileObject() const override;

    SECTION_OBJECT_IMPL(const NtKernelImpl<PtrType>& kernel, const GuestVirtualAddress& gva);
    SECTION_OBJECT_IMPL(const NtKernelImpl<PtrType>& kernel,
                        std::unique_ptr<OBJECT_HEADER_IMPL<PtrType>>&& object_header);

  private:
    const NtKernelImpl<PtrType>& kernel_;

    const structs::SECTION_OBJECT* section_;
    const structs::SEGMENT_OBJECT* segment_;

    guest_ptr<char[]> section_buffer_;
    guest_ptr<char[]> segment_buffer_;

    mutable std::recursive_mutex mtx_;
    mutable std::optional<CONTROL_AREA_IMPL<PtrType>> ControlArea_;
};

} // namespace nt
} // namespace windows
} // namespace introvirt