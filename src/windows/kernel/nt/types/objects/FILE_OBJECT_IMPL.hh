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

#include "DEVICE_OBJECT_IMPL.hh"
#include "OBJECT_IMPL.hh"
#include "windows/kernel/nt/structs/structs.hh"
#include "windows/kernel/nt/types/UNICODE_STRING_IMPL.hh"

#include <introvirt/core/memory/guest_ptr.hh>
#include <introvirt/fwd.hh>
#include <introvirt/windows/kernel/nt/types/UNICODE_STRING.hh>
#include <introvirt/windows/kernel/nt/types/objects/DEVICE_OBJECT.hh>
#include <introvirt/windows/kernel/nt/types/objects/FILE_OBJECT.hh>

#include <mutex>
#include <optional>

namespace introvirt {
namespace windows {
namespace nt {

template <typename PtrType>
class FILE_OBJECT_IMPL final : public OBJECT_IMPL<PtrType, FILE_OBJECT> {
  public:
    const DEVICE_OBJECT* DeviceObject() const override;
    std::string FileName() const override;

    bool DeletePending() const override;
    void DeletePending(bool value) override;

    FileObjectFlags Flags() const override;
    void Flags(FileObjectFlags flags) override;

    bool DeleteAccess() const override;
    void DeleteAccess(bool value) override;

    bool SharedDelete() const override;
    void SharedDelete(bool value) override;

    /**
     * @brief Get the drive letter of the file object
     */
    std::string drive_letter() const override;

    /**
     * @brief Get the full path, drive letter included
     */
    std::string full_path() const override;

    FILE_OBJECT_IMPL(const NtKernelImpl<PtrType>& kernel, const GuestVirtualAddress& gva);
    FILE_OBJECT_IMPL(const NtKernelImpl<PtrType>& kernel,
                     std::unique_ptr<OBJECT_HEADER_IMPL<PtrType>>&& object_header);

  private:
    const NtKernelImpl<PtrType>& kernel_;
    const structs::FILE_OBJECT* offsets_;
    guest_ptr<char[]> buffer_;

    mutable std::recursive_mutex mtx_;
    mutable std::optional<UNICODE_STRING_IMPL<PtrType>> FileName_;
    mutable std::optional<DEVICE_OBJECT_IMPL<PtrType>> DeviceObject_;
    mutable std::string drive_letter_;
};

} // namespace nt
} // namespace windows
} // namespace introvirt