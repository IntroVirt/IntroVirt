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

#include <introvirt/core/domain/Guest.hh>
#include <introvirt/windows/kernel/SystemCallConverter.hh>

#include <introvirt/fwd.hh>

#include <cstdint>
#include <set>
#include <string>

namespace introvirt {
namespace windows {

/**
 * @brief A representation of a Windows Guest OS
 */
class WindowsGuest : public Guest {
  public:
    /**
     * @brief Get the system call conversion class
     *
     * @return the system call conversion class
     */
    virtual const SystemCallConverter& syscalls() const = 0;

    /**
     * @brief Get the Nt kernel
     *
     * @return A reference to the NT kernel parser
     */
    virtual nt::NtKernel& kernel() = 0;

    /**
     * @copydoc WindowsGuest::kernel()
     */
    virtual const nt::NtKernel& kernel() const = 0;

    /**
     * @brief Get the Domain instance the guest is running on
     *
     * @return The domain instance
     */
    virtual Domain& domain() = 0;

    /**
     * @copydoc WindowsGuest::domain()
     */
    virtual const Domain& domain() const = 0;

    /**
     * @brief Configure a system call filter intercept
     *
     * @param filter The filter to configure
     * @param index The index to configure
     * @param value The value to set
     * @return true If the bitmap was configured
     * @return false If the guest does not support the given index
     */
    virtual bool set_system_call_filter(SystemCallFilter& filter, SystemCallIndex index,
                                        bool value) const = 0;

    /**
     * @brief Configure a system call filter for all supported calls
     *
     * This method will enable all supported system calls in the filter.
     * It does not turn the filter on, or clear out existing entries.
     *
     * @param filter The filter to configure
     */
    virtual void default_syscall_filter(SystemCallFilter& filter) const = 0;

    /**
     * @brief Get the available system call categories
     *
     */
    static std::set<std::string> syscall_categories();

    /**
     * @brief Enable a specific category for a filter
     *
     * @param category The category to enable
     * @param filter The system call filter to enable for
     */
    virtual void enable_category(const std::string& category, SystemCallFilter& filter) const = 0;

    virtual ~WindowsGuest() = default;

  private:
};

} // namespace windows
} // namespace introvirt