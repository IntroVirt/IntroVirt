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
#include "FILE_OBJECT_IMPL.hh"
#include "windows/kernel/nt/NtKernelImpl.hh"

#include <introvirt/core/exception/VirtualAddressNotPresentException.hh>
#include <introvirt/windows/kernel/nt/NtKernel.hh>
#include <introvirt/windows/kernel/nt/const/ObjectType.hh>

#include <boost/algorithm/string.hpp>
#include <log4cxx/logger.h>

#include <cstdint>

static log4cxx::LoggerPtr
    logger(log4cxx::Logger::getLogger("introvirt.windows.kernel.nt.types.FILE_OBJECT"));

namespace introvirt {
namespace windows {
namespace nt {

template <typename PtrType>
const DEVICE_OBJECT* FILE_OBJECT_IMPL<PtrType>::DeviceObject() const {
    std::lock_guard lock(mtx_);
    if (!DeviceObject_.has_value()) {
        const uint64_t pDeviceObject = offsets_->DeviceObject.get<PtrType>(buffer_);
        DeviceObject_.emplace(kernel_, this->address().create(pDeviceObject));
    }
    return &(*DeviceObject_);
}

template <typename PtrType>
std::string FILE_OBJECT_IMPL<PtrType>::FileName() const {
    std::lock_guard lock(mtx_);
    if (!FileName_.has_value()) {
        const GuestVirtualAddress pFileName = this->address() + offsets_->FileName.offset();
        try {
            FileName_.emplace(pFileName);
        } catch (VirtualAddressNotPresentException& ex) {
            LOG4CXX_WARN(logger, "Failed to read FILE_OBJECT::FileName " << pFileName);
            // TODO(pape): Sometimes this is just not readable.
            //             Appears to be a valid pointer but can't be accessed.
            //             WinDbg also fails to access it.
            return std::string();
        }
    }
    return FileName_->utf8();
}

template <typename PtrType>
bool FILE_OBJECT_IMPL<PtrType>::DeletePending() const {
    return offsets_->DeletePending.get<uint8_t>(buffer_);
}

template <typename PtrType>
void FILE_OBJECT_IMPL<PtrType>::DeletePending(bool deletePending) {
    offsets_->DeletePending.set<uint8_t>(buffer_, deletePending);
}

template <typename PtrType>
FileObjectFlags FILE_OBJECT_IMPL<PtrType>::Flags() const {
    return FileObjectFlags(offsets_->Flags.get<uint32_t>(buffer_));
}

template <typename PtrType>
void FILE_OBJECT_IMPL<PtrType>::Flags(FileObjectFlags flags) {
    offsets_->Flags.set<uint32_t>(buffer_, flags.value());
}

template <typename PtrType>
bool FILE_OBJECT_IMPL<PtrType>::DeleteAccess() const {
    return offsets_->DeleteAccess.get<uint8_t>(buffer_);
}

template <typename PtrType>
void FILE_OBJECT_IMPL<PtrType>::DeleteAccess(bool deleteAccess) {
    offsets_->DeleteAccess.set<uint8_t>(buffer_, deleteAccess);
}

template <typename PtrType>
bool FILE_OBJECT_IMPL<PtrType>::SharedDelete() const {
    return offsets_->SharedDelete.get<uint8_t>(buffer_);
}

template <typename PtrType>
void FILE_OBJECT_IMPL<PtrType>::SharedDelete(bool sharedDelete) {
    offsets_->SharedDelete.set<uint8_t>(buffer_, sharedDelete);
}

template <typename PtrType>
std::string FILE_OBJECT_IMPL<PtrType>::drive_letter() const {
    if (drive_letter_.empty()) {
        const DEVICE_OBJECT* device = DeviceObject();
        if (device != nullptr)
            drive_letter_ = kernel_.get_device_drive_letter(*device);
    }
    return drive_letter_;
}

template <typename PtrType>
std::string FILE_OBJECT_IMPL<PtrType>::full_path() const {
    return drive_letter() + FileName();
}

template <typename PtrType>
FILE_OBJECT_IMPL<PtrType>::FILE_OBJECT_IMPL(const NtKernelImpl<PtrType>& kernel,
                                            const GuestVirtualAddress& gva)
    : OBJECT_IMPL<PtrType, FILE_OBJECT>(kernel, gva, ObjectType::File), kernel_(kernel),
      offsets_(LoadOffsets<structs::FILE_OBJECT>(kernel)) {

    buffer_.reset(gva, offsets_->size());
}

template <typename PtrType>
FILE_OBJECT_IMPL<PtrType>::FILE_OBJECT_IMPL(
    const NtKernelImpl<PtrType>& kernel,
    std::unique_ptr<OBJECT_HEADER_IMPL<PtrType>>&& object_header)
    : OBJECT_IMPL<PtrType, FILE_OBJECT>(kernel, std::move(object_header), ObjectType::File),
      kernel_(kernel), offsets_(LoadOffsets<structs::FILE_OBJECT>(kernel)) {

    buffer_.reset(OBJECT_IMPL<PtrType, FILE_OBJECT>::address(), offsets_->size());
}

std::shared_ptr<FILE_OBJECT> FILE_OBJECT::make_shared(const NtKernel& kernel,
                                                      const GuestVirtualAddress& gva) {
    if (kernel.x64())
        return std::make_shared<FILE_OBJECT_IMPL<uint64_t>>(
            static_cast<const NtKernelImpl<uint64_t>&>(kernel), gva);
    else
        return std::make_shared<FILE_OBJECT_IMPL<uint32_t>>(
            static_cast<const NtKernelImpl<uint32_t>&>(kernel), gva);
}

std::shared_ptr<FILE_OBJECT>
FILE_OBJECT::make_shared(const NtKernel& kernel, std::unique_ptr<OBJECT_HEADER>&& object_header) {
    if (kernel.x64()) {
        std::unique_ptr<OBJECT_HEADER_IMPL<uint64_t>> object_header_impl;
        object_header_impl.reset(
            static_cast<OBJECT_HEADER_IMPL<uint64_t>*>(object_header.release()));
        return std::make_shared<FILE_OBJECT_IMPL<uint64_t>>(
            static_cast<const NtKernelImpl<uint64_t>&>(kernel), std::move(object_header_impl));
    } else {
        std::unique_ptr<OBJECT_HEADER_IMPL<uint32_t>> object_header_impl;
        object_header_impl.reset(
            static_cast<OBJECT_HEADER_IMPL<uint32_t>*>(object_header.release()));
        return std::make_shared<FILE_OBJECT_IMPL<uint32_t>>(
            static_cast<const NtKernelImpl<uint32_t>&>(kernel), std::move(object_header_impl));
    }
}

enum FoFlags {
    FO_FILE_OPEN = 0x00000001,
    FO_SYNCHRONOUS_IO = 0x00000002,
    FO_ALERTABLE_IO = 0x00000004,
    FO_NO_INTERMEDIATE_BUFFERING = 0x00000008,
    FO_WRITE_THROUGH = 0x00000010,
    FO_SEQUENTIAL_ONLY = 0x00000020,
    FO_CACHE_SUPPORTED = 0x00000040,
    FO_NAMED_PIPE = 0x00000080,
    FO_STREAM_FILE = 0x00000100,
    FO_MAILSLOT = 0x00000200,
    FO_GENERATE_AUDIT_ON_CLOSE = 0x00000400,
    FO_QUEUE_IRP_TO_THREAD = FO_GENERATE_AUDIT_ON_CLOSE,
    FO_DIRECT_DEVICE_OPEN = 0x00000800,
    FO_FILE_MODIFIED = 0x00001000,
    FO_FILE_SIZE_CHANGED = 0x00002000,
    FO_CLEANUP_COMPLETE = 0x00004000,
    FO_TEMPORARY_FILE = 0x00008000,
    FO_DELETE_ON_CLOSE = 0x00010000,
    FO_OPENED_CASE_SENSITIVE = 0x00020000,
    FO_HANDLE_CREATED = 0x00040000,
    FO_FILE_FAST_IO_READ = 0x00080000,
    FO_RANDOM_ACCESS = 0x00100000,
    FO_FILE_OPEN_CANCELLED = 0x00200000,
    FO_VOLUME_OPEN = 0x00400000,
    FO_REMOTE_ORIGIN = 0x01000000,
    FO_SKIP_COMPLETION_PORT = 0x02000000,
    FO_SKIP_SET_EVENT = 0x04000000,
    FO_SKIP_SET_FAST_IO = 0x08000000
};

bool FileObjectFlags::FO_FILE_OPEN() const { return value_ & FoFlags::FO_FILE_OPEN; }
bool FileObjectFlags::FO_SYNCHRONOUS_IO() const { return value_ & FoFlags::FO_SYNCHRONOUS_IO; }
bool FileObjectFlags::FO_ALERTABLE_IO() const { return value_ & FoFlags::FO_ALERTABLE_IO; }
bool FileObjectFlags::FO_NO_INTERMEDIATE_BUFFERING() const {
    return value_ & FoFlags::FO_NO_INTERMEDIATE_BUFFERING;
}
bool FileObjectFlags::FO_WRITE_THROUGH() const { return value_ & FoFlags::FO_WRITE_THROUGH; }
bool FileObjectFlags::FO_SEQUENTIAL_ONLY() const { return value_ & FoFlags::FO_SEQUENTIAL_ONLY; }
bool FileObjectFlags::FO_CACHE_SUPPORTED() const { return value_ & FoFlags::FO_CACHE_SUPPORTED; }
bool FileObjectFlags::FO_NAMED_PIPE() const { return value_ & FoFlags::FO_NAMED_PIPE; }
bool FileObjectFlags::FO_STREAM_FILE() const { return value_ & FoFlags::FO_STREAM_FILE; }
bool FileObjectFlags::FO_MAILSLOT() const { return value_ & FoFlags::FO_MAILSLOT; }
bool FileObjectFlags::FO_GENERATE_AUDIT_ON_CLOSE() const {
    return value_ & FoFlags::FO_GENERATE_AUDIT_ON_CLOSE;
}
bool FileObjectFlags::FO_QUEUE_IRP_TO_THREAD() const {
    return value_ & FoFlags::FO_QUEUE_IRP_TO_THREAD;
}
bool FileObjectFlags::FO_DIRECT_DEVICE_OPEN() const {
    return value_ & FoFlags::FO_DIRECT_DEVICE_OPEN;
}
bool FileObjectFlags::FO_FILE_MODIFIED() const { return value_ & FoFlags::FO_FILE_MODIFIED; }
bool FileObjectFlags::FO_FILE_SIZE_CHANGED() const {
    return value_ & FoFlags::FO_FILE_SIZE_CHANGED;
}
bool FileObjectFlags::FO_CLEANUP_COMPLETE() const { return value_ & FoFlags::FO_CLEANUP_COMPLETE; }
bool FileObjectFlags::FO_TEMPORARY_FILE() const { return value_ & FoFlags::FO_TEMPORARY_FILE; }
bool FileObjectFlags::FO_DELETE_ON_CLOSE() const { return value_ & FoFlags::FO_DELETE_ON_CLOSE; }
bool FileObjectFlags::FO_OPENED_CASE_SENSITIVE() const {
    return value_ & FoFlags::FO_OPENED_CASE_SENSITIVE;
}
bool FileObjectFlags::FO_HANDLE_CREATED() const { return value_ & FoFlags::FO_HANDLE_CREATED; }
bool FileObjectFlags::FO_FILE_FAST_IO_READ() const {
    return value_ & FoFlags::FO_FILE_FAST_IO_READ;
}
bool FileObjectFlags::FO_RANDOM_ACCESS() const { return value_ & FoFlags::FO_RANDOM_ACCESS; }
bool FileObjectFlags::FO_FILE_OPEN_CANCELLED() const {
    return value_ & FoFlags::FO_FILE_OPEN_CANCELLED;
}
bool FileObjectFlags::FO_VOLUME_OPEN() const { return value_ & FoFlags::FO_VOLUME_OPEN; }
bool FileObjectFlags::FO_REMOTE_ORIGIN() const { return value_ & FoFlags::FO_REMOTE_ORIGIN; }
bool FileObjectFlags::FO_SKIP_COMPLETION_PORT() const {
    return value_ & FoFlags::FO_SKIP_COMPLETION_PORT;
}
bool FileObjectFlags::FO_SKIP_SET_EVENT() const { return value_ & FoFlags::FO_SKIP_SET_EVENT; }
bool FileObjectFlags::FO_SKIP_SET_FAST_IO() const { return value_ & FoFlags::FO_SKIP_SET_FAST_IO; }

template class FILE_OBJECT_IMPL<uint32_t>;
template class FILE_OBJECT_IMPL<uint64_t>;

} // namespace nt
} // namespace windows
} /* namespace introvirt */
