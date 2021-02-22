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
#include "OBJECT_DIRECTORY_IMPL.hh"
#include "OBJECT_HEADER_IMPL.hh"
#include "windows/kernel/nt/NtKernelImpl.hh"

#include <introvirt/core/memory/guest_ptr.hh>
#include <introvirt/windows/kernel/nt/NtKernel.hh>
#include <introvirt/windows/kernel/nt/const/ObjectType.hh>

#include <log4cxx/logger.h>

namespace introvirt {
namespace windows {
namespace nt {

static log4cxx::LoggerPtr
    logger(log4cxx::Logger::getLogger("introvirt.windows.kernel.nt.types.OBJECT_DIRECTORY"));

template <typename PtrType>
const std::vector<std::shared_ptr<OBJECT>>& OBJECT_DIRECTORY_IMPL<PtrType>::objects() const {
    return objects_;
}

template <typename PtrType>
std::vector<std::shared_ptr<OBJECT>>& OBJECT_DIRECTORY_IMPL<PtrType>::objects() {
    return objects_;
}

template <typename PtrType>
void OBJECT_DIRECTORY_IMPL<PtrType>::init(const NtKernelImpl<PtrType>& kernel,
                                          const GuestVirtualAddress& gva) {

    const structs::OBJECT_DIRECTORY* object_directory;
    const structs::OBJECT_DIRECTORY_ENTRY* object_directory_entry;

    object_directory = LoadOffsets<structs::OBJECT_DIRECTORY>(kernel);
    object_directory_entry = LoadOffsets<structs::OBJECT_DIRECTORY_ENTRY>(kernel);
    buffer_.reset(gva, object_directory->size());

    static const size_t HashBucketCount = object_directory->HashBuckets.size() / sizeof(PtrType);

    for (size_t i = 0; i < HashBucketCount; ++i) {
        const uint16_t bucketOffset =
            object_directory->HashBuckets.offset() + (sizeof(PtrType) * i);

        PtrType entryAddress = *reinterpret_cast<const PtrType*>(buffer_.get() + bucketOffset);

        if (entryAddress) {
            do {
                try {
                    guest_ptr<char[]> entry_buffer(gva.create(entryAddress),
                                                   object_directory_entry->size());
                    const PtrType pObject =
                        object_directory_entry->Object.get<PtrType>(entry_buffer);
                    if (pObject) {
                        LOG4CXX_TRACE(logger,
                                      "OBJECT_DIRECTORY Entry: pObject: 0x" << std::hex << pObject);
                        try {
                            auto object = OBJECT::make_shared(kernel, gva.create(pObject));
                            if (object)
                                objects_.push_back(std::move(object));
                        } catch (TraceableException& ex) {
                            // NOTE: I'm seeing invalid objects in this directory even with
                            // WinDbg on Windows 10. WinDbg also shows the memory address as
                            // not present

                            // LOG4CXX_DEBUG(logger, "Failed to create object: " << ex);
                        }
                    }
                    entryAddress = object_directory_entry->ChainLink.get<PtrType>(entry_buffer);
                    // LOG4CXX_DEBUG(logger, "ChainLink: 0x" << std::hex << entryAddress);
                } catch (TraceableException& ex) {
                    LOG4CXX_DEBUG(logger, "Exception: " << ex);
                    entryAddress = 0;
                }
            } while (entryAddress != 0u);
        }
    }
}

template <typename PtrType>
OBJECT_DIRECTORY_IMPL<PtrType>::OBJECT_DIRECTORY_IMPL(const NtKernelImpl<PtrType>& kernel,
                                                      const GuestVirtualAddress& gva)
    : OBJECT_IMPL<PtrType, OBJECT_DIRECTORY>(kernel, gva, ObjectType::Directory) {

    init(kernel, gva);
}

template <typename PtrType>
OBJECT_DIRECTORY_IMPL<PtrType>::OBJECT_DIRECTORY_IMPL(
    const NtKernelImpl<PtrType>& kernel, std::unique_ptr<OBJECT_HEADER_IMPL<PtrType>>&& objHeader)
    : OBJECT_IMPL<PtrType, OBJECT_DIRECTORY>(kernel, std::move(objHeader), ObjectType::Directory) {

    init(kernel, OBJECT_IMPL<PtrType, OBJECT_DIRECTORY>::address());
}

std::shared_ptr<OBJECT_DIRECTORY> OBJECT_DIRECTORY::make_shared(const NtKernel& kernel,
                                                                const GuestVirtualAddress& gva) {
    if (kernel.x64())
        return std::make_shared<OBJECT_DIRECTORY_IMPL<uint64_t>>(
            static_cast<const NtKernelImpl<uint64_t>&>(kernel), gva);
    else
        return std::make_shared<OBJECT_DIRECTORY_IMPL<uint32_t>>(
            static_cast<const NtKernelImpl<uint32_t>&>(kernel), gva);
}

std::shared_ptr<OBJECT_DIRECTORY>
OBJECT_DIRECTORY::make_shared(const NtKernel& kernel,
                              std::unique_ptr<OBJECT_HEADER>&& object_header) {
    if (kernel.x64()) {
        std::unique_ptr<OBJECT_HEADER_IMPL<uint64_t>> object_header_impl;
        object_header_impl.reset(
            static_cast<OBJECT_HEADER_IMPL<uint64_t>*>(object_header.release()));
        return std::make_shared<OBJECT_DIRECTORY_IMPL<uint64_t>>(
            static_cast<const NtKernelImpl<uint64_t>&>(kernel), std::move(object_header_impl));
    } else {
        std::unique_ptr<OBJECT_HEADER_IMPL<uint32_t>> object_header_impl;
        object_header_impl.reset(
            static_cast<OBJECT_HEADER_IMPL<uint32_t>*>(object_header.release()));
        return std::make_shared<OBJECT_DIRECTORY_IMPL<uint32_t>>(
            static_cast<const NtKernelImpl<uint32_t>&>(kernel), std::move(object_header_impl));
    }
}

template class OBJECT_DIRECTORY_IMPL<uint32_t>;
template class OBJECT_DIRECTORY_IMPL<uint64_t>;

} // namespace nt
} // namespace windows
} // namespace introvirt
