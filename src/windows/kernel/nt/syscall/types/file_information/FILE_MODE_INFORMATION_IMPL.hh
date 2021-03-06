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
#include <introvirt/windows/kernel/nt/syscall/types/file_information/FILE_MODE_INFORMATION.hh>

namespace introvirt {
namespace windows {
namespace nt {

namespace structs {

struct _FILE_MODE_INFORMATION {
    uint32_t Mode;
};

} // namespace structs

class FILE_MODE_INFORMATION_IMPL final : public FILE_MODE_INFORMATION {
  public:
    uint32_t Mode() const override { return ptr_->Mode; }
    void Mode(uint32_t value) override { ptr_->Mode = value; }

    FILE_INFORMATION_CLASS FileInformationClass() const override {
        return FILE_INFORMATION_CLASS::FileModeInformation;
    }

    guest_ptr<void> ptr() const override { return ptr_; }

    uint32_t buffer_size() const override { return buffer_size_; }

    void write(std::ostream& os, const std::string& linePrefix = "") const override;

    Json::Value json() const override;

    FILE_MODE_INFORMATION_IMPL(const guest_ptr<void>& ptr, uint32_t buffer_size);

  private:
    const uint32_t buffer_size_;
    guest_ptr<structs::_FILE_MODE_INFORMATION> ptr_;
};

} // namespace nt
} // namespace windows
} // namespace introvirt