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

namespace introvirt {

/**
 * @brief Base class for system call filtering
 *
 * This class may be used on its own, but checks will be performed in libintrovirt rather than the
 * hypervisor, which will perform worse.
 *
 * Ideally, the hypervisor library exends this class, and has the hypervisor map in the bitmap page.
 * Then, system call filtering can be performed at the hypervisor level, rather than in
 * libintrovirt.
 */
class SystemCallFilter {
  public:
    /**
     * @brief Mask incoming system calls with the given mask before checking for a match
     *
     * This allows each check to be performed with a mask.
     * For example, if the system call 0xABCD comes in, and the mask is set to 0xFF,
     * the filter will attempt to match 0xCD.
     *
     * @param mask The mask to set
     */
    void mask(uint64_t mask);

    /**
     * @brief Get the mask that is in use by the filter
     *
     * @return the system call mask
     */
    uint64_t mask() const;

    /**
     * @brief Set if the filter is enabled
     * @param enabled If set to true, enable the bitmap
     */
    void enabled(bool enabled);

    /**
     * @brief Check if the filter is enabled
     *
     * If the filter is not enabled, matches() will always return true.
     *
     * @return true if the bitmap is enabled
     * @return false if the bitmap is not enabled
     */
    bool enabled() const;

    /**
     * @brief Check if the filter matches the given system call event
     *
     * matches() will always return true if the filter is not enabled.
     *
     * @param event The incoming event
     * @return true if the event mathces out filter
     * @return false if the event does not match our filter
     */
    bool matches(const Event& event) const;

    /**
     * @brief Check if the filter matches the given system call event
     *
     * matches() will always return true if the filter is not enabled.
     *
     * This version is more naive, and assumes the call number is held in rax.
     * This seems like a reasonable assumption.
     *
     * @param event The incoming event
     * @return true if the event mathces out filter
     * @return false if the event does not match our filter
     */
    bool matches(const Vcpu& vcpu) const;

    /**
     * @brief Set a filter entry for 32-bit system calls
     *
     * @param index The system call number to set
     * @param enabled Set to true to enable intercepts for the given index
     */
    void set_32(uint32_t index, bool enabled);

    /**
     * @brief Set a filter entry for 64-bit system calls
     *
     * @param index The system call number to set
     * @param enabled Set to true to enable intercepts for the given index
     */
    void set_64(uint32_t index, bool enabled);

    /**
     * @brief Clear the filter
     */
    void clear();

    /**
     * @brief Construct a new System Call Filter object
     */
    SystemCallFilter();

    /**
     * @brief Destroy the instance
     */
    virtual ~SystemCallFilter();

  private:
    class IMPL;
    std::unique_ptr<IMPL> pImpl_;
};

} // namespace introvirt
