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
#include <introvirt/windows/kernel/nt/fwd.hh>

#include <cstdint>
#include <memory>

namespace introvirt {
namespace windows {
namespace nt {

class HANDLE_TABLE_ENTRY {
  public:
    /** @returns The value of the entry */
    virtual uint64_t Value() const = 0;

    /** @returns The OBJECT_HEADER for this handle */
    virtual std::unique_ptr<OBJECT_HEADER> ObjectHeader() const = 0;

    /** @returns The access level granted to the object through this handle. */
    virtual ACCESS_MASK GrantedAccess() const = 0;

    /** Set the granted access mask after the handle is created. */
    virtual void GrantedAccess(const ACCESS_MASK& mask) = 0;

    /** @returns The handle number. */
    virtual uint64_t Handle() const = 0;

    /**
     * @brief Get the address of the structure
     */
    virtual GuestVirtualAddress address() const = 0;

    virtual ~HANDLE_TABLE_ENTRY() = default;
};

} /* namespace nt */
} /* namespace windows */
} /* namespace introvirt */
