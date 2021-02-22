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
#pragma once

#include "OBJECT.hh"

#include <introvirt/windows/kernel/nt/fwd.hh>

#include <string>

namespace introvirt {
namespace windows {
namespace nt {

class FileObjectFlags {
  public:
    bool FO_FILE_OPEN() const;
    bool FO_SYNCHRONOUS_IO() const;
    bool FO_ALERTABLE_IO() const;
    bool FO_NO_INTERMEDIATE_BUFFERING() const;
    bool FO_WRITE_THROUGH() const;
    bool FO_SEQUENTIAL_ONLY() const;
    bool FO_CACHE_SUPPORTED() const;
    bool FO_NAMED_PIPE() const;
    bool FO_STREAM_FILE() const;
    bool FO_MAILSLOT() const;
    bool FO_GENERATE_AUDIT_ON_CLOSE() const;
    bool FO_QUEUE_IRP_TO_THREAD() const;
    bool FO_DIRECT_DEVICE_OPEN() const;
    bool FO_FILE_MODIFIED() const;
    bool FO_FILE_SIZE_CHANGED() const;
    bool FO_CLEANUP_COMPLETE() const;
    bool FO_TEMPORARY_FILE() const;
    bool FO_DELETE_ON_CLOSE() const;
    bool FO_OPENED_CASE_SENSITIVE() const;
    bool FO_HANDLE_CREATED() const;
    bool FO_FILE_FAST_IO_READ() const;
    bool FO_RANDOM_ACCESS() const;
    bool FO_FILE_OPEN_CANCELLED() const;
    bool FO_VOLUME_OPEN() const;
    bool FO_REMOTE_ORIGIN() const;
    bool FO_SKIP_COMPLETION_PORT() const;
    bool FO_SKIP_SET_EVENT() const;
    bool FO_SKIP_SET_FAST_IO() const;
    uint32_t value() const { return value_; }

    FileObjectFlags(uint32_t value) : value_(value) {}

  private:
    const uint32_t value_;
};

class FILE_OBJECT : public OBJECT {
  public:
    virtual const DEVICE_OBJECT* DeviceObject() const = 0;
    virtual std::string FileName() const = 0;

    virtual bool DeletePending() const = 0;
    virtual void DeletePending(bool value) = 0;

    virtual FileObjectFlags Flags() const = 0;
    virtual void Flags(FileObjectFlags flags) = 0;

    virtual bool DeleteAccess() const = 0;
    virtual void DeleteAccess(bool value) = 0;

    virtual bool SharedDelete() const = 0;
    virtual void SharedDelete(bool value) = 0;

    /**
     * @brief Get the drive letter of the file object
     */
    virtual std::string drive_letter() const = 0;

    /**
     * @brief Get the full path, drive letter included
     */
    virtual std::string full_path() const = 0;

    static std::shared_ptr<FILE_OBJECT> make_shared(const NtKernel& kernel,
                                                    const GuestVirtualAddress& gva);

    static std::shared_ptr<FILE_OBJECT> make_shared(const NtKernel& kernel,
                                                    std::unique_ptr<OBJECT_HEADER>&& object_header);

    virtual ~FILE_OBJECT() = default;
};

} /* namespace nt */
} /* namespace windows */
} /* namespace introvirt */
