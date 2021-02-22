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

#include "KvmVcpu.hh"
#include "kvm_introspection.hh"

#include "core/event/HypervisorEvent.hh"

#include <introvirt/core/domain/Domain.hh>

#include <introvirt/core/memory/GuestVirtualAddress.hh>
#include <introvirt/util/compiler.hh>

namespace introvirt {
namespace kvm {

class KvmDomain;
class KvmVcpu;

class KvmEvent final : public HypervisorEvent {
  public:
    Vcpu& vcpu() override { return vcpu_; }
    const Vcpu& vcpu() const override { return vcpu_; }

    Domain& domain() override { return vcpu_.domain(); }
    const Domain& domain() const override { return vcpu_.domain(); }

    EventType type() const override { return original_event_type_; }

    FastCallType system_call_type() const override { return original_fastcall_type_; }

    uint64_t syscall_return_address() const override { return original_fastcall_return_; }

    int control_register() const override { return event_data_.cr_access.cr; }
    uint64_t control_register_value() const override { return event_data_.cr_access.value; }

    uint64_t msr_index() const override { return 0; }
    uint64_t msr_value() const override { return 0; }

    x86::Exception exception() const override {
        switch (event_data_.trap.vector) {
        case BP_VECTOR:
            return x86::Exception::INT3;
        default:
            return x86::Exception::UNKNOWN;
        }
    }

    GuestPhysicalAddress mem_access_physical_address() const override {
        return GuestPhysicalAddress(domain(), event_data_.mem_event.gpa);
    }

    bool mem_access_read() const override {
        return event_data_.mem_event.error_code & PFERR_USER_MASK;
    }
    bool mem_access_write() const override {
        return event_data_.mem_event.error_code & PFERR_WRITE_MASK;
    }
    bool mem_access_execute() const override {
        return event_data_.mem_event.error_code & PFERR_FETCH_MASK;
    }

    /**
     * @brief Get the unique ID associated with this event
     */
    uint64_t id() const override { return event_id_; }

    void discard(bool value) override;

    KvmEvent(KvmVcpu& vcpu, struct kvm_introspection_event& event_data);

    ~KvmEvent() override;

  protected:
    KvmVcpu& vcpu_;
    struct kvm_introspection_event& event_data_;

    const uint64_t event_id_;

    /*
     * If the original thread was an EVENT_FAST_SYSCALL,
     * and we suspended the thread, we need to get it back to a
     * system call at the end of the event. Otherwise we'd get a duplicate
     * EVENT_FAST_SYSCALL event.
     */
    EventType original_event_type_;
    FastCallType original_fastcall_type_;
    uint64_t original_fastcall_return_;

    bool discarded_ = false;
};

/**
 * @brief Create a KvmEvent instance
 *
 * @param vcpu The vcpu that triggered the event
 * @param event_data The event data from KVM
 * @return A KvmEvent instance
 */
std::unique_ptr<HypervisorEvent> create_kvm_event(KvmVcpu& vcpu,
                                                  struct kvm_introspection_event& event_data);

} // namespace kvm
} // namespace introvirt