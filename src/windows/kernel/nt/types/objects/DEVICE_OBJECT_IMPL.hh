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

#include "OBJECT_IMPL.hh"
#include "windows/kernel/nt/structs/structs.hh"

#include <introvirt/core/memory/guest_ptr.hh>
#include <introvirt/fwd.hh>
#include <introvirt/windows/kernel/nt/types/objects/DEVICE_OBJECT.hh>

#include <mutex>
#include <optional>

namespace introvirt {
namespace windows {
namespace nt {

template <typename PtrType>
class DRIVER_OBJECT_IMPL;

template <typename PtrType>
class DEVICE_OBJECT_IMPL final : public OBJECT_IMPL<PtrType, DEVICE_OBJECT> {
  public:
    nt::DeviceType DeviceType() const override;
    std::string DeviceName() const override;
    const DRIVER_OBJECT& DriverObject() const override;

    DEVICE_OBJECT_IMPL(const NtKernelImpl<PtrType>& kernel, const GuestVirtualAddress& gva);
    DEVICE_OBJECT_IMPL(const NtKernelImpl<PtrType>& kernel,
                       std::unique_ptr<OBJECT_HEADER_IMPL<PtrType>>&& object_header);

    ~DEVICE_OBJECT_IMPL();

  private:
    const NtKernelImpl<PtrType>& kernel_;
    const structs::DEVICE_OBJECT* offsets_;
    guest_ptr<char[]> buffer_;

    mutable std::recursive_mutex mtx_;
    mutable std::unique_ptr<DRIVER_OBJECT_IMPL<PtrType>> DriverObject_;
};

} // namespace nt
} // namespace windows
} // namespace introvirt