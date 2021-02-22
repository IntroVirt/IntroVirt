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
#include "KEVENT_IMPL.hh"
#include "windows/kernel/nt/NtKernelImpl.hh"

#include <introvirt/windows/kernel/nt/NtKernel.hh>
#include <introvirt/windows/kernel/nt/const/ObjectType.hh>

namespace introvirt {
namespace windows {
namespace nt {

template <typename PtrType>
KEVENT_IMPL<PtrType>::KEVENT_IMPL(const NtKernelImpl<PtrType>& kernel,
                                  const GuestVirtualAddress& gva)
    : DISPATCHER_OBJECT_IMPL<PtrType, KEVENT>(kernel, gva, ObjectType::Event) {}

template <typename PtrType>
KEVENT_IMPL<PtrType>::KEVENT_IMPL(const NtKernelImpl<PtrType>& kernel,
                                  std::unique_ptr<OBJECT_HEADER_IMPL<PtrType>>&& object_header)
    : DISPATCHER_OBJECT_IMPL<PtrType, KEVENT>(kernel, std::move(object_header), ObjectType::Event) {
}

std::shared_ptr<KEVENT> KEVENT::make_shared(const NtKernel& kernel,
                                            const GuestVirtualAddress& gva) {
    if (kernel.x64())
        return std::make_shared<KEVENT_IMPL<uint64_t>>(
            static_cast<const NtKernelImpl<uint64_t>&>(kernel), gva);
    else
        return std::make_shared<KEVENT_IMPL<uint32_t>>(
            static_cast<const NtKernelImpl<uint32_t>&>(kernel), gva);
}

std::shared_ptr<KEVENT> KEVENT::make_shared(const NtKernel& kernel,
                                            std::unique_ptr<OBJECT_HEADER>&& object_header) {
    if (kernel.x64()) {
        std::unique_ptr<OBJECT_HEADER_IMPL<uint64_t>> object_header_impl;
        object_header_impl.reset(
            static_cast<OBJECT_HEADER_IMPL<uint64_t>*>(object_header.release()));
        return std::make_shared<KEVENT_IMPL<uint64_t>>(
            static_cast<const NtKernelImpl<uint64_t>&>(kernel), std::move(object_header_impl));
    } else {
        std::unique_ptr<OBJECT_HEADER_IMPL<uint32_t>> object_header_impl;
        object_header_impl.reset(
            static_cast<OBJECT_HEADER_IMPL<uint32_t>*>(object_header.release()));
        return std::make_shared<KEVENT_IMPL<uint32_t>>(
            static_cast<const NtKernelImpl<uint32_t>&>(kernel), std::move(object_header_impl));
    }
}

template class KEVENT_IMPL<uint32_t>;
template class KEVENT_IMPL<uint64_t>;

} /* namespace nt */
} /* namespace windows */
} /* namespace introvirt */
