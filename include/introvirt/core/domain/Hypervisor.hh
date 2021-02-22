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

#include <introvirt/core/fwd.hh>

#include <cstdint>
#include <memory>
#include <string>
#include <vector>

namespace introvirt {

/**
 * @brief Information about a domain
 *
 * A vector of DomainInformation is by Hypervisor::get_running_domains()
 */
class DomainInformation {
  public:
    /**
     * @brief The name of the domain
     */
    std::string domain_name;

    /**
     * @brief The numeric idenifier of the domain
     */
    uint32_t domain_id;
};

/**
 * @brief A abstract class for managing a hypervisor
 */
class Hypervisor {
  public:
    /**
     * @brief Attach to a Domain based on numeric identifier
     *
     * @param domain_id The numeric identifier for the domain
     * @return The attached domain
     * @throws DomainBusyException If the domain is already attached to by an IntroVirt process
     * @throws NoSuchDomainException If the domain could not be found using the given domain_id
     */
    virtual std::unique_ptr<Domain> attach_domain(uint32_t domain_id) = 0;

    /**
     * @brief Attach to a Domain based on name
     *
     * @param domain_name The name of the domain
     * @return The attached domain
     * @throws DomainBusyException If the domain is already attached to by an IntroVirt process
     * @throws NoSuchDomainException If the domain could not be found using the given domain_id
     */
    virtual std::unique_ptr<Domain> attach_domain(const std::string& domain_name) = 0;

    /**
     * @brief Get information about the running domains
     *
     * @return A vector of domain information
     */
    virtual std::vector<DomainInformation> get_running_domains() = 0;

    /**
     * @brief Gets the name of the hypervisor
     *
     * @return The name of the hypervisor (i.e., "KVM")
     */
    virtual std::string hypervisor_name() const = 0;

    /**
     * @brief Gets the version of the hypervisor as a string
     *
     * @return The version of the hypervisor as a string
     */
    virtual std::string hypervisor_version() const = 0;

    /**
     * @brief Gets the version of the hypervisor's IntroVirt patch as a string
     *
     * @return the version of the hypervisor's IntroVirt patch
     */
    virtual std::string hypervisor_patch_version() const = 0;

    /**
     * @brief Gets the name of the library used for interacting with the hypervisor
     *
     * @return The name of the library (i.e., "libintrovirt-kvm")
     */
    virtual std::string library_name() const = 0;

    /**
     * @brief Gets the version of the hypervisor library as a string
     *
     * @return The version of the hypervisor as a string
     */
    virtual std::string library_version() const = 0;

    /**
     * @brief Destroy the instance
     */
    virtual ~Hypervisor();

    /**
     * @brief Get an instance of the hypervisor
     *
     * This will try to find the correct hypervisor (KVM/Xen)
     *
     * @return A hypervisor instance
     * @throws UnsupportedHypervisorException If no hypervisor could be attached to
     */
    static std::unique_ptr<Hypervisor> instance();

  protected:
    /**
     * @brief Construct a new Hypervisor object
     */
    Hypervisor();
};

} // namespace introvirt