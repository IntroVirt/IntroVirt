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
#include "CONTROL_AREA_IMPL.hh"
#include "windows/kernel/nt/NtKernelImpl.hh"

#include <log4cxx/logger.h>

namespace introvirt {
namespace windows {
namespace nt {

static log4cxx::LoggerPtr
    logger(log4cxx::Logger::getLogger("introvirt.windows.kernel.nt.types.CONTROL_AREA"));

template <typename PtrType>
const SEGMENT* CONTROL_AREA_IMPL<PtrType>::Segment() const {
    if (!Segment_) {
        const GuestVirtualAddress pSegment =
            gva_.create(control_area_->Segment.get<PtrType>(buffer_));

        if (pSegment) {
            Segment_.emplace(kernel_, pSegment, this);
        } else {
            return nullptr;
        }
    }
    return &(*Segment_);
}

template <typename PtrType>
const FILE_OBJECT* CONTROL_AREA_IMPL<PtrType>::FileObject() const {
    if (!FileObject_) {
        if (control_area_->File.get<uint32_t>(buffer_) != 0) {
            // Mask off the RefCnt bits from _EX_FAST_REF
            // Observed to be 3 bits on x86 and 4 bits on x64, but
            // just read it from the structure here to be safe.
            const uint64_t mask = ~(control_area_->FilePointer.RefCnt.mask());
            const GuestVirtualAddress pFileObject =
                gva_.create(control_area_->FilePointer.Object.get<PtrType>(buffer_) & mask);

            if (pFileObject)
                FileObject_.emplace(kernel_, pFileObject);
            else
                return nullptr;
        } else {
            return nullptr;
        }
    }

    return &(*FileObject_);
}

template <typename PtrType>
CONTROL_AREA_IMPL<PtrType>::CONTROL_AREA_IMPL(const NtKernelImpl<PtrType>& kernel,
                                              const GuestVirtualAddress& gva)
    : kernel_(kernel), gva_(gva) {

    // Load our offsets
    control_area_ = LoadOffsets<structs::CONTROL_AREA>(kernel_);

    // Map in the structure. Doing one mapping is a lot cheaper than mapping every field.
    buffer_.reset(gva_, control_area_->size());
}

template class CONTROL_AREA_IMPL<uint32_t>;
template class CONTROL_AREA_IMPL<uint64_t>;

} // namespace nt
} // namespace windows
} // namespace introvirt
