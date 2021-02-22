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

#include <introvirt/core/memory/guest_ptr.hh>
#include <introvirt/windows/kernel/nt/syscall/types/fs_information/FILE_FS_DEVICE_INFORMATION.hh>

namespace introvirt {
namespace windows {
namespace nt {

namespace structs {

struct _FILE_FS_DEVICE_INFORMATION {
    uint32_t DeviceType;
    uint32_t Characteristics;
};

static_assert(sizeof(_FILE_FS_DEVICE_INFORMATION) == 0x8);

} // namespace structs

class FILE_FS_DEVICE_INFORMATION_IMPL final : public FILE_FS_DEVICE_INFORMATION {
  public:
    nt::DeviceType DeviceType() const override {
        return static_cast<nt::DeviceType>(data_->DeviceType);
    }
    void DeviceType(nt::DeviceType type) override {
        data_->DeviceType = static_cast<uint32_t>(type);
    }

    uint32_t Characteristics() const override { return data_->Characteristics; }
    void Characteristics(uint32_t characteristics) override {
        data_->Characteristics = characteristics;
    }

    FS_INFORMATION_CLASS FsInformationClass() const override {
        return FS_INFORMATION_CLASS::FileFsDeviceInformation;
    }

    GuestVirtualAddress address() const override { return gva_; }

    uint32_t buffer_size() const override { return buffer_size_; }

    void write(std::ostream& os, const std::string& linePrefix = "") const override;

    Json::Value json() const override;

    FILE_FS_DEVICE_INFORMATION_IMPL(const GuestVirtualAddress& gva, uint32_t buffer_size);

  private:
    const GuestVirtualAddress gva_;
    const uint32_t buffer_size_;
    guest_ptr<structs::_FILE_FS_DEVICE_INFORMATION> data_;
};

} // namespace nt
} // namespace windows
} // namespace introvirt