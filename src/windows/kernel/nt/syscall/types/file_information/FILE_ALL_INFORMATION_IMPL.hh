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

#include "FILE_ACCESS_INFORMATION_IMPL.hh"
#include "FILE_ALIGNMENT_INFORMATION_IMPL.hh"
#include "FILE_BASIC_INFORMATION_IMPL.hh"
#include "FILE_EA_INFORMATION_IMPL.hh"
#include "FILE_INTERNAL_INFORMATION_IMPL.hh"
#include "FILE_MODE_INFORMATION_IMPL.hh"
#include "FILE_NAME_INFORMATION_IMPL.hh"
#include "FILE_POSITION_INFORMATION_IMPL.hh"
#include "FILE_STANDARD_INFORMATION_IMPL.hh"

#include <introvirt/core/memory/guest_ptr.hh>
#include <introvirt/windows/kernel/nt/syscall/types/file_information/FILE_ALL_INFORMATION.hh>

#include <optional>

namespace introvirt {
namespace windows {
namespace nt {

namespace structs {

struct _FILE_ALL_INFORMATION {
    _FILE_BASIC_INFORMATION BasicInformation;
    _FILE_STANDARD_INFORMATION StandardInformation;
    _FILE_INTERNAL_INFORMATION InternalInformation;
    _FILE_EA_INFORMATION EaInformation;
    _FILE_ACCESS_INFORMATION AccessInformation;
    _FILE_POSITION_INFORMATION PositionInformation;
    _FILE_MODE_INFORMATION ModeInformation;
    _FILE_ALIGNMENT_INFORMATION AlignmentInformation;
    _FILE_NAME_INFORMATION NameInformation;
};

} // namespace structs

class FILE_ALL_INFORMATION_IMPL final : public FILE_ALL_INFORMATION {
  public:
    FILE_BASIC_INFORMATION* BasicInformation() override;
    const FILE_BASIC_INFORMATION* BasicInformation() const override;

    FILE_STANDARD_INFORMATION* StandardInformation() override;
    const FILE_STANDARD_INFORMATION* StandardInformation() const override;

    FILE_INTERNAL_INFORMATION* InternalInformation() override;
    const FILE_INTERNAL_INFORMATION* InternalInformation() const override;

    FILE_EA_INFORMATION* EaInformation() override;
    const FILE_EA_INFORMATION* EaInformation() const override;

    FILE_ACCESS_INFORMATION* AccessInformation() override;
    const FILE_ACCESS_INFORMATION* AccessInformation() const override;

    FILE_POSITION_INFORMATION* PositionInformation() override;
    const FILE_POSITION_INFORMATION* PositionInformation() const override;

    FILE_MODE_INFORMATION* ModeInformation() override;
    const FILE_MODE_INFORMATION* ModeInformation() const override;

    FILE_ALIGNMENT_INFORMATION* AlignmentInformation() override;
    const FILE_ALIGNMENT_INFORMATION* AlignmentInformation() const override;

    FILE_NAME_INFORMATION* NameInformation() override;
    const FILE_NAME_INFORMATION* NameInformation() const override;

    FILE_INFORMATION_CLASS FileInformationClass() const override {
        return FILE_INFORMATION_CLASS::FileAllInformation;
    }

    GuestVirtualAddress address() const override { return gva_; }

    uint32_t buffer_size() const override { return buffer_size_; }

    void write(std::ostream& os, const std::string& linePrefix = "") const override;

    Json::Value json() const override;

    FILE_ALL_INFORMATION_IMPL(const GuestVirtualAddress& gva, uint32_t buffer_size);

  private:
    const GuestVirtualAddress gva_;
    const uint32_t buffer_size_;

    std::optional<FILE_BASIC_INFORMATION_IMPL> BasicInformation_;
    std::optional<FILE_STANDARD_INFORMATION_IMPL> StandardInformation_;
    std::optional<FILE_INTERNAL_INFORMATION_IMPL> InternalInformation_;
    std::optional<FILE_EA_INFORMATION_IMPL> EaInformation_;
    std::optional<FILE_ACCESS_INFORMATION_IMPL> AccessInformation_;
    std::optional<FILE_POSITION_INFORMATION_IMPL> PositionInformation_;
    std::optional<FILE_MODE_INFORMATION_IMPL> ModeInformation_;
    std::optional<FILE_ALIGNMENT_INFORMATION_IMPL> AlignmentInformation_;
    std::optional<FILE_NAME_INFORMATION_IMPL> NameInformation_;
};

} // namespace nt
} // namespace windows
} // namespace introvirt