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
#include "OBJECT_TYPE_IMPL.hh"
#include "windows/kernel/nt/NtKernelImpl.hh"

#include <introvirt/windows/exception/IncorrectTypeException.hh>
#include <introvirt/windows/kernel/nt/NtKernel.hh>

#include <introvirt/util/compiler.hh>

#include <log4cxx/logger.h>

namespace introvirt {
namespace windows {
namespace nt {

static log4cxx::LoggerPtr
    logger(log4cxx::Logger::getLogger("introvirt.windows.kernel.nt.types.OBJECT_TYPE"));

template <typename PtrType>
const std::string& OBJECT_TYPE_IMPL<PtrType>::Name() const {
    std::lock_guard lock(mtx_);
    if (!Name_) {
        const GuestVirtualAddress pName = this->address() + offsets_->Name.offset();
        Name_.emplace(pName);
    }
    return Name_->utf8();
}

template <typename PtrType>
uint32_t OBJECT_TYPE_IMPL<PtrType>::TotalNumberOfObjects() const {
    return offsets_->TotalNumberOfObjects.get<uint32_t>(buffer_);
}

template <typename PtrType>
uint32_t OBJECT_TYPE_IMPL<PtrType>::TotalNumberOfHandles() const {
    return offsets_->TotalNumberOfHandles.get<uint32_t>(buffer_);
}

template <typename PtrType>
uint32_t OBJECT_TYPE_IMPL<PtrType>::HighWaterNumberOfObjects() const {
    return offsets_->HighWaterNumberOfObjects.get<uint32_t>(buffer_);
}

template <typename PtrType>
uint32_t OBJECT_TYPE_IMPL<PtrType>::HighWaterNumberOfHandles() const {
    return offsets_->HighWaterNumberOfHandles.get<uint32_t>(buffer_);
}

template <typename PtrType>
uint32_t OBJECT_TYPE_IMPL<PtrType>::Key() const {
    return offsets_->Key.get<uint32_t>(buffer_);
}

template <typename PtrType>
uint8_t OBJECT_TYPE_IMPL<PtrType>::Index() const {
    // TODO(papes): On XP this is a 32-bit field, not sure if it works the same way though
    return offsets_->Index.get<uint8_t>(buffer_);
}

template <typename PtrType>
OBJECT_TYPE_IMPL<PtrType>::OBJECT_TYPE_IMPL(const NtKernelImpl<PtrType>& kernel,
                                            const GuestVirtualAddress& gva)
    : OBJECT_IMPL<PtrType, OBJECT_TYPE>(kernel, gva, ObjectType::Type), kernel_(kernel),
      offsets_(LoadOffsets<structs::OBJECT_TYPE>(kernel)) {

    buffer_.reset(gva, offsets_->size());
}

template <typename PtrType>
OBJECT_TYPE_IMPL<PtrType>::OBJECT_TYPE_IMPL(
    const NtKernelImpl<PtrType>& kernel,
    std::unique_ptr<OBJECT_HEADER_IMPL<PtrType>>&& object_header)
    : OBJECT_IMPL<PtrType, OBJECT_TYPE>(kernel, std::move(object_header), ObjectType::Type),
      kernel_(kernel), offsets_(LoadOffsets<structs::OBJECT_TYPE>(kernel)) {

    buffer_.reset(OBJECT_IMPL<PtrType, OBJECT_TYPE>::address(), offsets_->size());
}

std::shared_ptr<OBJECT_TYPE> OBJECT_TYPE::make_shared(const NtKernel& kernel,
                                                      const GuestVirtualAddress& gva) {
    if (kernel.x64())
        return std::make_shared<OBJECT_TYPE_IMPL<uint64_t>>(
            static_cast<const NtKernelImpl<uint64_t>&>(kernel), gva);
    else
        return std::make_shared<OBJECT_TYPE_IMPL<uint32_t>>(
            static_cast<const NtKernelImpl<uint32_t>&>(kernel), gva);
}

std::shared_ptr<OBJECT_TYPE>
OBJECT_TYPE::make_shared(const NtKernel& kernel, std::unique_ptr<OBJECT_HEADER>&& object_header) {
    if (kernel.x64()) {
        std::unique_ptr<OBJECT_HEADER_IMPL<uint64_t>> object_header_impl;
        object_header_impl.reset(
            static_cast<OBJECT_HEADER_IMPL<uint64_t>*>(object_header.release()));
        return std::make_shared<OBJECT_TYPE_IMPL<uint64_t>>(
            static_cast<const NtKernelImpl<uint64_t>&>(kernel), std::move(object_header_impl));
    } else {
        std::unique_ptr<OBJECT_HEADER_IMPL<uint32_t>> object_header_impl;
        object_header_impl.reset(
            static_cast<OBJECT_HEADER_IMPL<uint32_t>*>(object_header.release()));
        return std::make_shared<OBJECT_TYPE_IMPL<uint32_t>>(
            static_cast<const NtKernelImpl<uint32_t>&>(kernel), std::move(object_header_impl));
    }
}

template class OBJECT_TYPE_IMPL<uint32_t>;
template class OBJECT_TYPE_IMPL<uint64_t>;

} /* namespace nt */
} /* namespace windows */
} /* namespace introvirt */
