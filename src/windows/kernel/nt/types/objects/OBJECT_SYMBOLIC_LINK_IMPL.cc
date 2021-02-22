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
#include "OBJECT_SYMBOLIC_LINK_IMPL.hh"
#include "windows/kernel/nt/NtKernelImpl.hh"

#include <introvirt/windows/kernel/nt/NtKernel.hh>

#include <log4cxx/logger.h>

namespace introvirt {
namespace windows {
namespace nt {

static log4cxx::LoggerPtr
    logger(log4cxx::Logger::getLogger("introvirt.windows.kernel.nt.types.OBJECT_SYMBOLIC_LINK"));

template <typename PtrType>
std::string OBJECT_SYMBOLIC_LINK_IMPL<PtrType>::LinkTarget() const {
    // TODO(pape): Not sure what flag 0x10 actually is, but it seems to indicate the LinkTarget
    // field isn't valid.
    std::lock_guard lock(mtx_);
    if (!LinkTarget_ && !(Flags() & 0x10)) {
        GuestVirtualAddress pLinkTarget = this->address() + offsets_->LinkTarget.offset();
        LinkTarget_.emplace(pLinkTarget);
        return LinkTarget_->utf8();
    }
    return "";
}

template <typename PtrType>
uint32_t OBJECT_SYMBOLIC_LINK_IMPL<PtrType>::Flags() const {
    if (offsets_->Flags.exists()) {
        return offsets_->Flags.get<uint32_t>(buffer);
    }
    return 0;
}

template <typename PtrType>
OBJECT_SYMBOLIC_LINK_IMPL<PtrType>::OBJECT_SYMBOLIC_LINK_IMPL(const NtKernelImpl<PtrType>& kernel,
                                                              const GuestVirtualAddress& gva)
    : OBJECT_IMPL<PtrType, OBJECT_SYMBOLIC_LINK>(kernel, gva, ObjectType::SymbolicLink),
      kernel_(kernel), offsets_(LoadOffsets<structs::OBJECT_SYMBOLIC_LINK>(kernel)) {

    buffer.reset(gva, offsets_->size());
}

template <typename PtrType>
OBJECT_SYMBOLIC_LINK_IMPL<PtrType>::OBJECT_SYMBOLIC_LINK_IMPL(
    const NtKernelImpl<PtrType>& kernel,
    std::unique_ptr<OBJECT_HEADER_IMPL<PtrType>>&& object_header)
    : OBJECT_IMPL<PtrType, OBJECT_SYMBOLIC_LINK>(kernel, std::move(object_header),
                                                 ObjectType::SymbolicLink),
      kernel_(kernel), offsets_(LoadOffsets<structs::OBJECT_SYMBOLIC_LINK>(kernel)) {

    buffer.reset(OBJECT_IMPL<PtrType, OBJECT_SYMBOLIC_LINK>::address(), offsets_->size());
}

std::shared_ptr<OBJECT_SYMBOLIC_LINK>
OBJECT_SYMBOLIC_LINK::make_shared(const NtKernel& kernel, const GuestVirtualAddress& gva) {
    if (kernel.x64())
        return std::make_shared<OBJECT_SYMBOLIC_LINK_IMPL<uint64_t>>(
            static_cast<const NtKernelImpl<uint64_t>&>(kernel), gva);
    else
        return std::make_shared<OBJECT_SYMBOLIC_LINK_IMPL<uint32_t>>(
            static_cast<const NtKernelImpl<uint32_t>&>(kernel), gva);
}

std::shared_ptr<OBJECT_SYMBOLIC_LINK>
OBJECT_SYMBOLIC_LINK::make_shared(const NtKernel& kernel,
                                  std::unique_ptr<OBJECT_HEADER>&& object_header) {
    if (kernel.x64()) {
        std::unique_ptr<OBJECT_HEADER_IMPL<uint64_t>> object_header_impl;
        object_header_impl.reset(
            static_cast<OBJECT_HEADER_IMPL<uint64_t>*>(object_header.release()));
        return std::make_shared<OBJECT_SYMBOLIC_LINK_IMPL<uint64_t>>(
            static_cast<const NtKernelImpl<uint64_t>&>(kernel), std::move(object_header_impl));
    } else {
        std::unique_ptr<OBJECT_HEADER_IMPL<uint32_t>> object_header_impl;
        object_header_impl.reset(
            static_cast<OBJECT_HEADER_IMPL<uint32_t>*>(object_header.release()));
        return std::make_shared<OBJECT_SYMBOLIC_LINK_IMPL<uint32_t>>(
            static_cast<const NtKernelImpl<uint32_t>&>(kernel), std::move(object_header_impl));
    }
}

template class OBJECT_SYMBOLIC_LINK_IMPL<uint32_t>;
template class OBJECT_SYMBOLIC_LINK_IMPL<uint64_t>;

} // namespace nt
} // namespace windows
} // namespace introvirt