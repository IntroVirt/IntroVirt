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
#include "OBJECT_IMPL.hh"
#include "windows/kernel/nt/NtKernelImpl.hh"

#include "CM_KEY_BODY_IMPL.hh"
#include "DEVICE_OBJECT_IMPL.hh"
#include "DRIVER_OBJECT_IMPL.hh"
#include "FILE_OBJECT_IMPL.hh"
#include "KEVENT_IMPL.hh"
#include "OBJECT_DIRECTORY_IMPL.hh"
#include "OBJECT_SYMBOLIC_LINK_IMPL.hh"
#include "OBJECT_TYPE_IMPL.hh"
#include "PROCESS_IMPL.hh"
#include "SECTION_IMPL.hh"
#include "THREAD_IMPL.hh"
#include "TOKEN_IMPL.hh"

#include <introvirt/windows/kernel/nt/NtKernel.hh>

namespace introvirt {
namespace windows {
namespace nt {

template <typename PtrType>
static std::shared_ptr<OBJECT> make_shared_impl(const NtKernelImpl<PtrType>& kernel,
                                                std::unique_ptr<OBJECT_HEADER>&& object_header) {

    std::unique_ptr<OBJECT_HEADER_IMPL<PtrType>> object_header_impl(
        static_cast<OBJECT_HEADER_IMPL<PtrType>*>(object_header.release()));

    switch (object_header_impl->type()) {
    case ObjectType::Device:
        return std::make_shared<DEVICE_OBJECT_IMPL<PtrType>>(kernel, std::move(object_header_impl));
    case ObjectType::Directory:
        return std::make_shared<OBJECT_DIRECTORY_IMPL<PtrType>>(kernel,
                                                                std::move(object_header_impl));
    case ObjectType::Driver:
        return std::make_shared<DRIVER_OBJECT_IMPL<PtrType>>(kernel, std::move(object_header_impl));
    case ObjectType::Event:
        return std::make_shared<KEVENT_IMPL<PtrType>>(kernel, std::move(object_header_impl));
    case ObjectType::File:
        return std::make_shared<FILE_OBJECT_IMPL<PtrType>>(kernel, std::move(object_header_impl));
    case ObjectType::Key:
        return std::make_shared<CM_KEY_BODY_IMPL<PtrType>>(kernel, std::move(object_header_impl));
    case ObjectType::Process:
        return kernel.process(object_header_impl->Body());
    case ObjectType::Section:
        return SECTION::make_shared(kernel, std::move(object_header_impl));
    case ObjectType::SymbolicLink:
        return std::make_shared<OBJECT_SYMBOLIC_LINK_IMPL<PtrType>>(kernel,
                                                                    std::move(object_header_impl));
    case ObjectType::Thread:
        return kernel.thread(object_header_impl->Body());
    case ObjectType::Token:
        return std::make_shared<TOKEN_IMPL<PtrType>>(kernel, std::move(object_header_impl));
    case ObjectType::Type:
        return std::make_shared<OBJECT_TYPE_IMPL<PtrType>>(kernel, std::move(object_header_impl));
    default:
        // TODO(pape): Handle more objects?
        return std::make_shared<OBJECT_IMPL<PtrType>>(kernel, std::move(object_header_impl),
                                                      ObjectType::Unknown);
    }
}

std::shared_ptr<OBJECT> OBJECT::make_shared(const NtKernel& kernel,
                                            std::unique_ptr<OBJECT_HEADER>&& object_header) {
    if (kernel.x64())
        return make_shared_impl<uint64_t>(static_cast<const NtKernelImpl<uint64_t>&>(kernel),
                                          std::move(object_header));
    else
        return make_shared_impl<uint32_t>(static_cast<const NtKernelImpl<uint32_t>&>(kernel),
                                          std::move(object_header));
}

std::shared_ptr<OBJECT> OBJECT::make_shared(const NtKernel& kernel,
                                            const GuestVirtualAddress& gva) {
    size_t object_headerOffset = 0x18;
    std::unique_ptr<OBJECT_HEADER> object_header;

    if (kernel.x64()) {
        object_headerOffset *= 2;
        object_header = std::make_unique<OBJECT_HEADER_IMPL<uint64_t>>(
            static_cast<const NtKernelImpl<uint64_t>&>(kernel), gva - object_headerOffset);
    } else {
        object_header = std::make_unique<OBJECT_HEADER_IMPL<uint32_t>>(
            static_cast<const NtKernelImpl<uint32_t>&>(kernel), gva - object_headerOffset);
    }

    switch (object_header->type()) {
    case ObjectType::Process:
        return kernel.process(gva);
    case ObjectType::Thread:
        return kernel.thread(gva);
    default:
        return make_shared(kernel, std::move(object_header));
    }
}

template class OBJECT_IMPL<uint32_t>;
template class OBJECT_IMPL<uint64_t>;

} // namespace nt
} // namespace windows
} // namespace introvirt