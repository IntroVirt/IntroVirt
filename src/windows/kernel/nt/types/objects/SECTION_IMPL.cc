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
#include "SECTION_IMPL.hh"
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
    logger(log4cxx::Logger::getLogger("introvirt.windows.kernel.nt.types.SECTION"));

template <typename PtrType>
uint64_t SECTION_IMPL<PtrType>::StartingVpn() const {
    return section->StartingVpn.get<PtrType>(buffer);
}

template <typename PtrType>
uint64_t SECTION_IMPL<PtrType>::EndingVpn() const {
    return section->EndingVpn.get<PtrType>(buffer);
}

template <typename PtrType>
GuestVirtualAddress SECTION_IMPL<PtrType>::StartingVa() const {
    return this->address().create(StartingVpn() << x86::PageDirectory::PAGE_SHIFT);
}

template <typename PtrType>
GuestVirtualAddress SECTION_IMPL<PtrType>::EndingVa() const {
    return this->address().create(EndingVpn() << x86::PageDirectory::PAGE_SHIFT);
}

template <typename PtrType>
uint64_t SECTION_IMPL<PtrType>::SizeOfSection() const {
    return section->SizeOfSection.get<uint64_t>(buffer);
}

template <typename PtrType>
const CONTROL_AREA* SECTION_IMPL<PtrType>::ControlArea() const {
    std::lock_guard lock(mtx_);
    if (!ControlArea_) {
        const auto pControlArea = this->address().create(section->ControlArea.get<PtrType>(buffer));
        if (!pControlArea)
            return nullptr;
        ControlArea_.emplace(kernel_, pControlArea);
    }
    return &(*ControlArea_);
}

template <typename PtrType>
const FILE_OBJECT* SECTION_IMPL<PtrType>::FileObject() const {
    std::lock_guard lock(mtx_);
    if (!FileObject_) {
        const auto pFileObject = this->address().create(section->FileObject.get<PtrType>(buffer));
        FileObject_.emplace(kernel_, pFileObject);
    }
    return &(*FileObject_);
}

template <typename PtrType>
SECTION_IMPL<PtrType>::SECTION_IMPL(const NtKernelImpl<PtrType>& kernel,
                                    const GuestVirtualAddress& gva)
    : OBJECT_IMPL<PtrType, SECTION>(kernel, gva, ObjectType::Section), kernel_(kernel) {

    try {
        section = LoadOffsets<structs::SECTION>(kernel);
    } catch (TypeInformationException& ex) {
        LOG4CXX_DEBUG(logger, "Failed to load _SECTION from PDB: Possibly issue #66?");
        throw;
    }

    buffer.reset(gva, section->size());
}

template <typename PtrType>
SECTION_IMPL<PtrType>::SECTION_IMPL(const NtKernelImpl<PtrType>& kernel,
                                    std::unique_ptr<OBJECT_HEADER_IMPL<PtrType>>&& object_header)
    : OBJECT_IMPL<PtrType, SECTION>(kernel, std::move(object_header), ObjectType::Section),
      kernel_(kernel) {

    try {
        section = LoadOffsets<structs::SECTION>(kernel);
    } catch (TypeInformationException& ex) {
        LOG4CXX_DEBUG(logger, "Failed to load _SECTION from PDB: Possibly issue #66?");
        throw;
    }

    buffer.reset(OBJECT_IMPL<PtrType, SECTION>::address(), section->size());
}

std::shared_ptr<SECTION> SECTION::make_shared(const NtKernel& kernel,
                                              const GuestVirtualAddress& gva) {
    if (kernel.MajorVersion() >= 10) {
        if (kernel.x64())
            return std::make_shared<SECTION_IMPL<uint64_t>>(
                static_cast<const NtKernelImpl<uint64_t>&>(kernel), gva);
        else
            return std::make_shared<SECTION_IMPL<uint32_t>>(
                static_cast<const NtKernelImpl<uint32_t>&>(kernel), gva);
    } else {
        if (kernel.x64())
            return std::make_shared<SECTION_OBJECT_IMPL<uint64_t>>(
                static_cast<const NtKernelImpl<uint64_t>&>(kernel), gva);
        else
            return std::make_shared<SECTION_OBJECT_IMPL<uint32_t>>(
                static_cast<const NtKernelImpl<uint32_t>&>(kernel), gva);
    }
}

std::shared_ptr<SECTION> SECTION::make_shared(const NtKernel& kernel,
                                              std::unique_ptr<OBJECT_HEADER>&& object_header) {
    if (kernel.MajorVersion() >= 10) {
        if (kernel.x64()) {
            std::unique_ptr<OBJECT_HEADER_IMPL<uint64_t>> object_header_impl;
            object_header_impl.reset(
                static_cast<OBJECT_HEADER_IMPL<uint64_t>*>(object_header.release()));
            return std::make_shared<SECTION_IMPL<uint64_t>>(
                static_cast<const NtKernelImpl<uint64_t>&>(kernel), std::move(object_header_impl));
        } else {
            std::unique_ptr<OBJECT_HEADER_IMPL<uint32_t>> object_header_impl;
            object_header_impl.reset(
                static_cast<OBJECT_HEADER_IMPL<uint32_t>*>(object_header.release()));
            return std::make_shared<SECTION_IMPL<uint32_t>>(
                static_cast<const NtKernelImpl<uint32_t>&>(kernel), std::move(object_header_impl));
        }
    } else {
        if (kernel.x64()) {
            std::unique_ptr<OBJECT_HEADER_IMPL<uint64_t>> object_header_impl;
            object_header_impl.reset(
                static_cast<OBJECT_HEADER_IMPL<uint64_t>*>(object_header.release()));
            return std::make_shared<SECTION_OBJECT_IMPL<uint64_t>>(
                static_cast<const NtKernelImpl<uint64_t>&>(kernel), std::move(object_header_impl));
        } else {
            std::unique_ptr<OBJECT_HEADER_IMPL<uint32_t>> object_header_impl;
            object_header_impl.reset(
                static_cast<OBJECT_HEADER_IMPL<uint32_t>*>(object_header.release()));
            return std::make_shared<SECTION_OBJECT_IMPL<uint32_t>>(
                static_cast<const NtKernelImpl<uint32_t>&>(kernel), std::move(object_header_impl));
        }
    }
}

template class SECTION_IMPL<uint32_t>;
template class SECTION_IMPL<uint64_t>;

} // namespace nt
} // namespace windows
} // namespace introvirt
