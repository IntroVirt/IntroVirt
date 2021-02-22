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
#include "DRIVER_OBJECT_IMPL.hh"
#include "windows/kernel/nt/NtKernelImpl.hh"

#include <introvirt/windows/exception/InvalidIrpException.hh>
#include <introvirt/windows/kernel/nt/NtKernel.hh>
#include <introvirt/windows/kernel/nt/const/ObjectType.hh>

namespace introvirt {
namespace windows {
namespace nt {

template <typename PtrType>
const DEVICE_OBJECT* DRIVER_OBJECT_IMPL<PtrType>::DeviceObject() const {
    std::lock_guard lock(mtx_);
    if (!DeviceObject_) {
        const GuestVirtualAddress pDeviceObject =
            this->address().create(offsets_->DeviceObject.get<PtrType>(buffer_));

        if (pDeviceObject)
            DeviceObject_ = std::make_unique<DEVICE_OBJECT_IMPL<PtrType>>(kernel_, pDeviceObject);
        else
            return nullptr;
    }

    return DeviceObject_.get();
}

template <typename PtrType>
std::string DRIVER_OBJECT_IMPL<PtrType>::DriverName() const {
    std::lock_guard lock(mtx_);
    if (!DriverName_) {
        const GuestVirtualAddress pDriverName = this->address() + offsets_->DriverName.offset();
        DriverName_.emplace(pDriverName);
    }
    return DriverName_->utf8();
}

template <typename PtrType>
GuestVirtualAddress DRIVER_OBJECT_IMPL<PtrType>::MajorFunction(IRP_MJ irp) const {
    if (unlikely(irp > IRP_MJ::IRP_MJ_MAX))
        throw InvalidIrpException("IRP out of bounds");

    const uint16_t offset =
        offsets_->MajorFunction.offset() + (sizeof(PtrType) * static_cast<uint16_t>(irp));

    const PtrType pResult = *reinterpret_cast<const PtrType*>(buffer_.get() + offset);
    return this->address().create(pResult);
}

template <typename PtrType>
DRIVER_OBJECT_IMPL<PtrType>::DRIVER_OBJECT_IMPL(const NtKernelImpl<PtrType>& kernel,
                                                const GuestVirtualAddress& gva)
    : OBJECT_IMPL<PtrType, DRIVER_OBJECT>(kernel, gva, ObjectType::Driver), kernel_(kernel),
      offsets_(LoadOffsets<structs::DRIVER_OBJECT>(kernel)) {

    buffer_.reset(gva, offsets_->size());
}

template <typename PtrType>
DRIVER_OBJECT_IMPL<PtrType>::DRIVER_OBJECT_IMPL(
    const NtKernelImpl<PtrType>& kernel,
    std::unique_ptr<OBJECT_HEADER_IMPL<PtrType>>&& object_header)
    : OBJECT_IMPL<PtrType, DRIVER_OBJECT>(kernel, std::move(object_header), ObjectType::Driver),
      kernel_(kernel), offsets_(LoadOffsets<structs::DRIVER_OBJECT>(kernel)) {

    buffer_.reset(OBJECT_IMPL<PtrType, DRIVER_OBJECT>::address(), offsets_->size());
}

std::shared_ptr<DRIVER_OBJECT> DRIVER_OBJECT::make_shared(const NtKernel& kernel,
                                                          const GuestVirtualAddress& gva) {
    if (kernel.x64())
        return std::make_shared<DRIVER_OBJECT_IMPL<uint64_t>>(
            static_cast<const NtKernelImpl<uint64_t>&>(kernel), gva);
    else
        return std::make_shared<DRIVER_OBJECT_IMPL<uint32_t>>(
            static_cast<const NtKernelImpl<uint32_t>&>(kernel), gva);
}

std::shared_ptr<DRIVER_OBJECT>
DRIVER_OBJECT::make_shared(const NtKernel& kernel, std::unique_ptr<OBJECT_HEADER>&& object_header) {
    if (kernel.x64()) {
        std::unique_ptr<OBJECT_HEADER_IMPL<uint64_t>> object_header_impl;
        object_header_impl.reset(
            static_cast<OBJECT_HEADER_IMPL<uint64_t>*>(object_header.release()));
        return std::make_shared<DRIVER_OBJECT_IMPL<uint64_t>>(
            static_cast<const NtKernelImpl<uint64_t>&>(kernel), std::move(object_header_impl));
    } else {
        std::unique_ptr<OBJECT_HEADER_IMPL<uint32_t>> object_header_impl;
        object_header_impl.reset(
            static_cast<OBJECT_HEADER_IMPL<uint32_t>*>(object_header.release()));
        return std::make_shared<DRIVER_OBJECT_IMPL<uint32_t>>(
            static_cast<const NtKernelImpl<uint32_t>&>(kernel), std::move(object_header_impl));
    }
}

template class DRIVER_OBJECT_IMPL<uint32_t>;
template class DRIVER_OBJECT_IMPL<uint64_t>;

} /* namespace nt */
} /* namespace windows */
} /* namespace introvirt */
