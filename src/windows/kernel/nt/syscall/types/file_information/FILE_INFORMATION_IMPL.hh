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

#include <introvirt/windows/kernel/nt/syscall/types/file_information/FILE_INFORMATION.hh>

namespace introvirt {
namespace windows {
namespace nt {

class FILE_INFORMATION_IMPL final : public FILE_INFORMATION {
  public:
    FILE_INFORMATION_CLASS FileInformationClass() const override { return class_; }

    GuestVirtualAddress address() const override { return gva_; }

    uint32_t buffer_size() const override { return buffer_size_; }

    void write(std::ostream& os, const std::string& linePrefix = "") const override;

    Json::Value json() const override;

    FILE_INFORMATION_IMPL(FILE_INFORMATION_CLASS information_class, const GuestVirtualAddress& gva,
                          uint32_t buffer_size)
        : class_(information_class), gva_(gva), buffer_size_(buffer_size) {}

  private:
    const FILE_INFORMATION_CLASS class_;
    const GuestVirtualAddress gva_;
    const uint32_t buffer_size_;
};

} // namespace nt
} // namespace windows
} // namespace introvirt