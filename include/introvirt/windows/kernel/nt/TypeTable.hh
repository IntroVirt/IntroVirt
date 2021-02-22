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

#include <introvirt/core/memory/GuestVirtualAddress.hh>
#include <introvirt/windows/fwd.hh>
#include <introvirt/windows/kernel/nt/const/ObjectType.hh>

#include <cstdint>

namespace introvirt {
namespace windows {
namespace nt {

/**
 * @brief Class for managing NT object types.
 *
 * Windows does not keep object types consistent between versions.
 * Consequently, we normalize their values for consistency.
 *
 */
class TypeTable {
  public:
    /**
     * @brief Convert a native object type to our normalized representation
     *
     * @param type The native object type
     * @return The normalized ObjectType
     */
    virtual ObjectType normalize(uint32_t type) const = 0;

    /**
     * @brief Get the type of object from the pointer to an OBJECT_TYPE
     *
     * This is just used by XP, where objects don't contain an index.
     * Instead, they contain a pointer to an OBJECT_TYPE.
     *
     * @param address The address of the OBJECT_TYPE
     * @return The normalized object type
     */
    virtual ObjectType normalize(const GuestVirtualAddress& address) const = 0;

    /**
     * @brief Convert a normalized ObjectType to it's native representation
     *
     * @param type The ObjectType to convert
     * @return The native
     */
    virtual uint32_t native(ObjectType type) const = 0;

    virtual ~TypeTable() = default;
};

} // namespace nt
} // namespace windows
} // namespace introvirt