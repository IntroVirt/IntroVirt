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
#include "SECTION_OBJECT_IMPL.hh"
#include "windows/kernel/nt/NtKernelImpl.hh"

#include <introvirt/util/compiler.hh>
#include <introvirt/windows/kernel/nt/NtKernel.hh>
#include <introvirt/windows/kernel/nt/const/ObjectType.hh>

#include <log4cxx/logger.h>

namespace introvirt {
namespace windows {
namespace nt {

static log4cxx::LoggerPtr
    logger(log4cxx::Logger::getLogger("introvirt.windows.kernel.nt.types.SECTION_OBJECT"));

template <typename PtrType>
uint64_t SECTION_OBJECT_IMPL<PtrType>::StartingVpn() const {
    return section_->StartingVa.get<PtrType>(section_buffer_) >> x86::PageDirectory::PAGE_SHIFT;
}

template <typename PtrType>
uint64_t SECTION_OBJECT_IMPL<PtrType>::EndingVpn() const {
    return section_->EndingVa.get<PtrType>(section_buffer_) >> x86::PageDirectory::PAGE_SHIFT;
}

template <typename PtrType>
GuestVirtualAddress SECTION_OBJECT_IMPL<PtrType>::StartingVa() const {
    return this->address().create(section_->StartingVa.get<PtrType>(section_buffer_));
}

template <typename PtrType>
GuestVirtualAddress SECTION_OBJECT_IMPL<PtrType>::EndingVa() const {
    return this->address().create(section_->EndingVa.get<PtrType>(section_buffer_));
}

template <typename PtrType>
uint64_t SECTION_OBJECT_IMPL<PtrType>::SizeOfSection() const {
    return EndingVa() - StartingVa();
}

template <typename PtrType>
const CONTROL_AREA* SECTION_OBJECT_IMPL<PtrType>::ControlArea() const {
    std::lock_guard lock(mtx_);
    if (!ControlArea_) {
        const auto pControlArea =
            this->address().create(segment_->ControlArea.get<PtrType>(segment_buffer_));
        if (!pControlArea)
            return nullptr;
        ControlArea_.emplace(kernel_, pControlArea);
    }
    return &(*ControlArea_);
}

template <typename PtrType>
const FILE_OBJECT* SECTION_OBJECT_IMPL<PtrType>::FileObject() const {
    return ControlArea()->FileObject();
}

template <typename PtrType>
SECTION_OBJECT_IMPL<PtrType>::SECTION_OBJECT_IMPL(const NtKernelImpl<PtrType>& kernel,
                                                  const GuestVirtualAddress& gva)
    : OBJECT_IMPL<PtrType, SECTION>(kernel, gva, ObjectType::Section), kernel_(kernel) {

    section_ = LoadOffsets<structs::SECTION_OBJECT>(kernel);
    segment_ = LoadOffsets<structs::SEGMENT_OBJECT>(kernel);
    section_buffer_.reset(gva, section_->size());

    const auto pSegment = this->address().create(section_->Segment.get<PtrType>(section_buffer_));
    segment_buffer_.reset(pSegment, segment_->size());
}

template <typename PtrType>
SECTION_OBJECT_IMPL<PtrType>::SECTION_OBJECT_IMPL(
    const NtKernelImpl<PtrType>& kernel,
    std::unique_ptr<OBJECT_HEADER_IMPL<PtrType>>&& object_header)
    : OBJECT_IMPL<PtrType, SECTION>(kernel, std::move(object_header), ObjectType::Section),
      kernel_(kernel) {

    section_ = LoadOffsets<structs::SECTION_OBJECT>(kernel);
    segment_ = LoadOffsets<structs::SEGMENT_OBJECT>(kernel);
    section_buffer_.reset(OBJECT_IMPL<PtrType, SECTION>::address(), section_->size());

    const auto pSegment = this->address().create(section_->Segment.get<PtrType>(section_buffer_));
    segment_buffer_.reset(pSegment, segment_->size());
}

template class SECTION_OBJECT_IMPL<uint32_t>;
template class SECTION_OBJECT_IMPL<uint64_t>;

} // namespace nt
} // namespace windows
} // namespace introvirt
