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

#include "VcpuImpl.hh"
#include "core/arch/x86/IdtImpl.hh"

#include <introvirt/core/arch/arch.hh>
#include <introvirt/core/exception/NotImplementedException.hh>
#include <introvirt/core/exception/VirtualAddressNotPresentException.hh>
#include <introvirt/core/memory/GuestPhysicalAddress.hh>
#include <introvirt/core/memory/GuestVirtualAddress.hh>
#include <introvirt/core/memory/guest_ptr.hh>
#include <introvirt/core/syscall/SystemCallFilter.hh>
#include <introvirt/util/compiler.hh>

#include <log4cxx/logger.h>

static log4cxx::LoggerPtr logger(log4cxx::Logger::getLogger("introvirt.domain.Vcpu"));

namespace introvirt {

class VcpuImpl::IMPL {
  public:
    std::unique_ptr<x86::Tss> tss_;

    /*
     * This is weird and merits some explaination.
     * When a VCPU is cloned(), it uses the system call filter
     * from the original for consistency.
     *
     * Only the "true" Vcpu holds anything in the unique_ptr,
     * and all clones will point to it.
     */
    std::unique_ptr<SystemCallFilter> system_call_filter_alloc_;
    SystemCallFilter* system_call_filter_;

    Domain* domain_;
    uint32_t id_;

    IMPL(VcpuImpl& vcpu) {}
};

SystemCallFilter& VcpuImpl::system_call_filter() { return *pImpl_->system_call_filter_; }
const SystemCallFilter& VcpuImpl::system_call_filter() const {
    return *pImpl_->system_call_filter_;
}

int VcpuImpl::event_fd() const {
    throw NotImplementedException("Vcpu does not support event polling");
}
std::unique_ptr<HypervisorEvent> VcpuImpl::event() {
    throw NotImplementedException("Vcpu does not support event polling");
}

Domain& VcpuImpl::domain() { return *pImpl_->domain_; }
const Domain& VcpuImpl::domain() const { return *pImpl_->domain_; }

uint32_t VcpuImpl::id() const { return pImpl_->id_; }

x86::Segment VcpuImpl::segment(x86::SegmentSelector sel) const {
    auto table = (sel.table_indicator()) ? local_descriptor_table() : global_descriptor_table();
    return table.selector(sel);
}

x86::SegmentDescriptorTable VcpuImpl::global_descriptor_table() const {
    // Get the GDT base and limit from the registers
    const auto& regs = registers();
    return x86::SegmentDescriptorTable(GuestVirtualAddress(*this, regs.gdtr_base()),
                                       regs.gdtr_limit());
}

x86::SegmentDescriptorTable VcpuImpl::local_descriptor_table() const {
    // Get the LDT base and limit from the registers
    const auto& regs = registers();

    const auto ldt = regs.ldt();

    return x86::SegmentDescriptorTable(GuestVirtualAddress(*this, ldt.base()), ldt.limit());
}

std::unique_ptr<const x86::Idt> VcpuImpl::interrupt_descriptor_table() const {
    if (long_mode())
        return std::make_unique<x86::IdtImpl<uint64_t>>(*this);
    else
        return std::make_unique<x86::IdtImpl<uint32_t>>(*this);
}

const x86::Tss& VcpuImpl::task_state_segment() const { return *pImpl_->tss_; }

VcpuImpl::VcpuImpl(Domain& domain, uint32_t id) : pImpl_(std::make_unique<IMPL>(*this)) {
    pImpl_->domain_ = &domain;
    pImpl_->id_ = id;

    pImpl_->system_call_filter_alloc_ = std::make_unique<SystemCallFilter>();
    pImpl_->system_call_filter_ = pImpl_->system_call_filter_alloc_.get();

    pImpl_->tss_ = std::make_unique<x86::Tss>(*this);
}

bool VcpuImpl::long_mode() const { return registers().efer().lma(); }
bool VcpuImpl::long_compatibility_mode() const {
    return long_mode() == true && registers().cs_long_mode() == false;
}

VcpuImpl::VcpuImpl(const VcpuImpl& src) : pImpl_(std::make_unique<IMPL>(*this)) {
    pImpl_->domain_ = src.pImpl_->domain_;
    pImpl_->id_ = src.pImpl_->id_;
    pImpl_->system_call_filter_ = src.pImpl_->system_call_filter_;
}

VcpuImpl::VcpuImpl(VcpuImpl&&) noexcept = default;
VcpuImpl& VcpuImpl::operator=(VcpuImpl&&) noexcept = default;
VcpuImpl::~VcpuImpl() = default;

} // namespace introvirt
