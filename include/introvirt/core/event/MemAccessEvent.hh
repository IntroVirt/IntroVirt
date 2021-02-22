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

namespace introvirt {

/**
 * @brief Interface for intercepting memory accesses
 *
 * Event for intercepted memory read/write/execute.
 */
class MemAccessEvent {
  public:
    /**
     * @brief Returns true if the event was caused by a read attempt
     *
     * @return True if the fault was caused by a read
     */
    virtual bool read_violation() const = 0;

    /**
     * @brief Returns true if the event was caused by a write attempt
     *
     * @return True if the fault was caused by a write
     */
    virtual bool write_violation() const = 0;

    /**
     * @brief Returns true if the event was caused by am execute attempt
     *
     * @return True if the fault was caused by an execute
     */
    virtual bool execute_violation() const = 0;

    /**
     * @brief Get the faulting guest physical address
     *
     * @return The faulting guest physical address
     */
    virtual GuestPhysicalAddress physical_address() const = 0;

    virtual ~MemAccessEvent() = default;
};

} // namespace introvirt