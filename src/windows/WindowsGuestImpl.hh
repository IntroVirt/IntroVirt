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

#include "core/domain/GuestImpl.hh"
#include "windows/kernel/nt/NtKernelImpl.hh"
#include "windows/kernel/nt/structs/structs.hh"

#include <introvirt/windows/WindowsGuest.hh>

#include <optional>
#include <unordered_set>

namespace introvirt {
namespace windows {

template <typename PtrType>
class WindowsGuestImpl final : public WindowsGuest, public GuestImpl {
  public:
    std::unique_ptr<Event> filter_event(std::unique_ptr<HypervisorEvent>&& event) override;

    OS os() const override;

    bool x64() const override;

    GuestPageFaultResult handle_page_fault(const GuestVirtualAddress& gva,
                                           uint64_t& pte) const override;

    const SystemCallConverter& syscalls() const override;

    nt::NtKernel& kernel() override;
    const nt::NtKernel& kernel() const override;

    Domain& domain() override;
    const Domain& domain() const override;

    bool set_system_call_filter(SystemCallFilter& filter, SystemCallIndex index,
                                bool value) const override;

    void default_syscall_filter(SystemCallFilter& filter) const override;

    void enable_category(const std::string& category, SystemCallFilter& filter) const override;

    GuestVirtualAddress allocate(size_t& region_size, bool executable = false) override;
    void guest_free(GuestVirtualAddress& gva, size_t region_size) override;

    GuestImpl& impl() override { return *this; }
    const GuestImpl& impl() const override { return *this; }

    uint64_t get_current_thread_id(const Vcpu& vcpu) const override {
        auto& kpcr = static_cast<const nt::KPCR_IMPL<PtrType>&>(kernel_->kpcr(vcpu));
        return kpcr.current_thread_address();
    }

    WindowsGuestImpl(Domain& domain);

  private:
    static constexpr bool is64Bit() { return sizeof(PtrType) == sizeof(uint64_t); }

    template <typename PteType>
    GuestPageFaultResult handle_page_fault_internal(const GuestVirtualAddress& gva,
                                                    PteType& pte) const;

    template <typename PteType>
    GuestPageFaultResult handle_page_fault_mmvad(const GuestVirtualAddress& gva,
                                                 PteType& pte) const;

    template <typename PteType>
    GuestPageFaultResult handle_prototype_pte(const GuestVirtualAddress& gva, PteType& pte) const;

    const nt::structs::MMPTE_HARDWARE* mmpte_hardware_ = nullptr;
    const nt::structs::MMPTE_PROTOTYPE* mmpte_prototype_ = nullptr;
    const nt::structs::MMPTE_SOFTWARE* mmpte_software_ = nullptr;
    const nt::structs::MMPTE_TRANSITION* mmpte_transition_ = nullptr;

    Domain* const domain_;

    std::optional<SystemCallConverter> syscalls_;
    std::optional<nt::NtKernelImpl<PtrType>> kernel_;
};

} // namespace windows
} // namespace introvirt