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

#include "kvm_introspection.hh"

#include "KvmRegisters.hh"
#include "core/domain/VcpuImpl.hh"

#include <mutex>

namespace introvirt {
namespace kvm {

class KvmDomain;

/**
 * @brief Vcpu class for KVM
 */
class KvmVcpu final : public VcpuImpl {
  public:
    KvmRegisters& registers() override HOT;

    const KvmRegisters& registers() const override HOT;

    void pause() override;

    void resume() override;

    void intercept_system_calls(bool enabled) override;

    bool intercept_system_calls() const override;

    void intercept_cr_writes(int cr, bool enabled) override;

    bool intercept_cr_writes(int cr) const override;

    void intercept_exception(x86::Exception vector, bool enabled);

    bool intercept_exception(x86::Exception vector) const;

    void single_step(bool enabled) override;

    bool single_step() const override;

    void inject_exception(x86::Exception vector) override;

    void inject_exception(x86::Exception vector, int64_t error_code) override;

    void inject_exception(x86::Exception vector, int64_t error_code, uint64_t cr2) override;

    void inject_syscall() override;
    void inject_sysenter() override;

    void write_registers() override;

    int event_fd() const override;

    std::unique_ptr<HypervisorEvent> event() override;

    std::unique_ptr<Vcpu> clone() const override;

    bool handling_event() const override;

    void syscall_injection_start() override;
    void syscall_injection_end() override;

    void os_data(void* data) override;
    void* os_data() const override;

    void complete_event() override;

    /**
     * @brief Construct a new Kvm Vcpu object
     *
     * This class takes ownership of the handle once it is constructed.
     *
     * @param domain The domain the vcpu belongs to
     * @param id The identifier of the vcpu
     * @param fd The handle to the open KVM vcpu
     */
    KvmVcpu(KvmDomain& domain, uint32_t id, int fd);

    /**
     * @brief Copy constructor
     */
    KvmVcpu(const KvmVcpu&);

    /**
     * @brief Destroy the instance
     */
    ~KvmVcpu() override;

  private:
    void _send_command(unsigned long request, unsigned long value, const std::string& errstr);

  private:
    const uint32_t id_;
    const int fd_;

    mutable std::recursive_mutex mtx_;

    struct kvm_introspection_event event_data_;
    KvmRegisters registers_;

    void* os_data_ = nullptr;

    int pause_count_ = 0;

    std::array<uint8_t, 9> cr_hook_ = {};

    bool syscall_intercept_ = false;
    bool int3_intercept_ = false;
    bool single_stepping_ = false;
    bool in_event_ = false;
    int syscall_injection_count_ = 0;
    bool pause_loaded_registers_ = false;
};

} // namespace kvm
} // namespace introvirt