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

#include <introvirt/core/domain/Hypervisor.hh>

#include <string>

namespace introvirt {
namespace kvm {

/**
 * @brief Hypervisor class for KVM
 */
class KvmHypervisor final : public Hypervisor {
  public:
    std::unique_ptr<Domain> attach_domain(uint32_t domain_id) override;

    std::unique_ptr<Domain> attach_domain(const std::string& domain_name) override;

    std::vector<DomainInformation> get_running_domains() override;

    std::string hypervisor_name() const override;

    std::string hypervisor_version() const override;

    std::string hypervisor_patch_version() const override;

    std::string library_name() const override;

    std::string library_version() const override;

    /**
     * @brief Construct a new Kvm Hypervisor object
     */
    KvmHypervisor();

    /**
     * @brief Destroy the instance
     */
    ~KvmHypervisor() override;

  private:
    const int fd_;
    std::string kernel_version_;
    std::string hypervisor_patch_version_;
};

} // namespace kvm
} // namespace introvirt