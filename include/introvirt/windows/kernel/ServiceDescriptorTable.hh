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

#include "ServiceTable.hh"
#include "fwd.hh"

namespace introvirt {
namespace windows {

class ServiceDescriptorTableEntry;

/**
 * @brief Windows Service Descriptor Table
 *
 * The Service Descriptor Table holds system call information.
 */
class ServiceDescriptorTable {
  public:
    /**
     * @brief Get the service descriptor table entry at the given index
     *
     * @param index The index to retreive
     * @return ServiceDescriptorTableEntry&
     * @throw std::out_of_range if going past the end of the table
     */
    virtual const ServiceDescriptorTableEntry& entry(unsigned int index) const = 0;

    /**
     * @brief Get the number of entries in the table
     *
     * @return The number of entries in the table
     */
    virtual unsigned int count() const = 0;

    /**
     * @brief Create a new ServiceDescriptorTable instance
     *
     * @param kernel The guest kernel
     * @param gva The address of the service table
     * @return A service descriptor table instance
     */
    static std::unique_ptr<ServiceDescriptorTable> create(const nt::NtKernel& kernel,
                                                          const GuestVirtualAddress& gva);

    /**
     * @brief Destroy the instance
     */
    virtual ~ServiceDescriptorTable() = default;
};

/**
 * @brief An entry in the ServiceDescriptorTable
 */
class ServiceDescriptorTableEntry {
  public:
    /**
     * @brief Get the ServiceTable this entry points to
     *
     * @return The ServiceTable this entry points to
     */
    virtual const ServiceTable& service_table() const = 0;

    /**
     * @brief Destroy the instance
     */
    virtual ~ServiceDescriptorTableEntry() = default;
};

} // namespace windows
} // namespace introvirt