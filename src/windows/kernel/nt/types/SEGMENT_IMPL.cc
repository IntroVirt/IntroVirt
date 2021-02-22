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
#include "SEGMENT_IMPL.hh"
#include "windows/kernel/nt/NtKernelImpl.hh"
#include "windows/kernel/nt/types/CONTROL_AREA_IMPL.hh"

#include <introvirt/windows/kernel/nt/NtKernel.hh>

namespace introvirt {
namespace windows {
namespace nt {

template <typename PtrType>
uint64_t SEGMENT_IMPL<PtrType>::FirstMappedVa() const {
    return segment_->FirstMappedVa.get<PtrType>(buffer_);
}

template <typename PtrType>
uint64_t SEGMENT_IMPL<PtrType>::SizeOfSegment() const {
    return segment_->SizeOfSegment.get<uint64_t>(buffer_);
}

template <typename PtrType>
const CONTROL_AREA* SEGMENT_IMPL<PtrType>::ControlArea() const {
    if (control_area_ == nullptr) {
        const GuestVirtualAddress pControlArea =
            gva_.create(segment_->ControlArea.get<PtrType>(buffer_));
        if (pControlArea) {
            allocated_control_area_ =
                std::make_unique<CONTROL_AREA_IMPL<PtrType>>(kernel_, pControlArea);
            control_area_ = allocated_control_area_.get();
        }
    }
    return control_area_;
}

// TODO: Allow a CONTROL_AREA to pass itself in as parent and verify the address matches what we
// expect
template <typename PtrType>
SEGMENT_IMPL<PtrType>::SEGMENT_IMPL(const NtKernelImpl<PtrType>& kernel,
                                    const GuestVirtualAddress& gva,
                                    const CONTROL_AREA_IMPL<PtrType>* control_area)
    : kernel_(kernel), gva_(gva.create(gva.virtual_address() & 0xFFFFFFFFFFFFFFF8)),
      control_area_(control_area) {

    // Load our structure offsets
    segment_ = LoadOffsets<structs::SEGMENT>(kernel);

    // Map in the structure. Doing one mapping is a lot cheaper than mapping every field.
    buffer_.reset(gva_, segment_->size());
}

template class SEGMENT_IMPL<uint32_t>;
template class SEGMENT_IMPL<uint64_t>;

} // namespace nt
} // namespace windows
} // namespace introvirt
