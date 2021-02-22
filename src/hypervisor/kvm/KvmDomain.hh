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

#include "KvmHypervisor.hh"
#include "KvmVcpu.hh"

#include "core/domain/DomainImpl.hh"

#include <introvirt/util/compiler.hh>

#include <vector>

namespace introvirt {
namespace kvm {

/**
 * @brief Domain class for KVM
 */
class KvmDomain final : public DomainImpl {
  public:
    std::string name() const override;

    uint32_t id() const override;

    KvmVcpu& vcpu(uint32_t index) override;

    const KvmVcpu& vcpu(uint32_t index) const override;

    uint32_t vcpu_count() const override;

    void intercept_mem_access(uint64_t gfn, bool on_read, bool on_write, bool on_execute) override;

    void clear_mem_access_intercepts() override;

    void intercept_exception(x86::Exception vector, bool enabled) override;

    bool intercept_exception(x86::Exception vector) const override;

    const KvmHypervisor& hypervisor() const override;

    GuestMemoryMapping map_pfns(const uint64_t* pfns, size_t count) const override HOT;

    KvmDomain(const KvmHypervisor& hypervisor, const std::string& name, uint32_t id, int fd);
    ~KvmDomain() override;

  private:
    const KvmHypervisor& hypervisor_;
    const std::string name_;
    const uint32_t id_;
    const int fd_;

    /*
     * Ideally we'd just directly hold the KvmVcpus, but they
     * don't have move semantics because of the std::atomic_int.
     */
    std::vector<std::unique_ptr<KvmVcpu>> vcpus_;

    bool intercept_int3_ = false;
    std::atomic_int syscall_injection_ = 0;
};

} // namespace kvm
} // namespace introvirt