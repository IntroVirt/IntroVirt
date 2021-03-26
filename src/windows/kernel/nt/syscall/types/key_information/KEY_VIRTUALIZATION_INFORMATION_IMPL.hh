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
#include <introvirt/windows/kernel/nt/syscall/types/key_information/KEY_VIRTUALIZATION_INFORMATION.hh>

namespace introvirt {
namespace windows {
namespace nt {

namespace structs {

struct __attribute__((ms_struct)) _KEY_VIRTUALIZATION_INFORMATION {
    uint32_t VirtualizationCandidate : 1;
    uint32_t VirtualizationEnabled : 1;
    uint32_t VirtualTarget : 1;
    uint32_t VirtualStore : 1;
    uint32_t VirtualSource : 1;
    uint32_t Reserved : 27;
};

static_assert(sizeof(_KEY_VIRTUALIZATION_INFORMATION) == 0x4);

} // namespace structs

class KEY_VIRTUALIZATION_INFORMATION_IMPL final : public KEY_VIRTUALIZATION_INFORMATION {
  public:
    bool VirtualizationCandidate() const override { return ptr_->VirtualizationCandidate; }
    void VirtualizationCandidate(bool value) override { ptr_->VirtualizationCandidate = value; }

    bool VirtualizationEnabled() const override { return ptr_->VirtualizationEnabled; }
    void VirtualizationEnabled(bool value) override { ptr_->VirtualizationEnabled = value; }

    bool VirtualTarget() const override { return ptr_->VirtualTarget; }
    void VirtualTarget(bool value) override { ptr_->VirtualTarget = value; }

    bool VirtualStore() const override { return ptr_->VirtualStore; }
    void VirtualStore(bool value) override { ptr_->VirtualStore = value; }

    bool VirtualSource() const override { return ptr_->VirtualSource; }
    void VirtualSource(bool value) override { ptr_->VirtualSource = value; }

    KEY_INFORMATION_CLASS KeyInformationClass() const override {
        return KEY_INFORMATION_CLASS::KeyVirtualizationInformation;
    }

    guest_ptr<void> ptr() const override { return ptr_; }

    uint32_t buffer_size() const override { return buffer_size_; }

    void write(std::ostream& os, const std::string& linePrefix = "") const override;

    Json::Value json() const override;

    KEY_VIRTUALIZATION_INFORMATION_IMPL(const guest_ptr<void>& ptr, uint32_t buffer_size);

  private:
    const uint32_t buffer_size_;
    guest_ptr<structs::_KEY_VIRTUALIZATION_INFORMATION> ptr_;
};

} // namespace nt
} // namespace windows
} // namespace introvirt