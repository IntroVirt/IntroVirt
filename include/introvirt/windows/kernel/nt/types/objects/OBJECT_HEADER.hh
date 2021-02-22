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

#include <introvirt/windows/kernel/nt/types/objects/OBJECT_HEADER_CREATOR_INFO.hh>
#include <introvirt/windows/kernel/nt/types/objects/OBJECT_HEADER_HANDLE_INFO.hh>
#include <introvirt/windows/kernel/nt/types/objects/OBJECT_HEADER_NAME_INFO.hh>
#include <introvirt/windows/kernel/nt/types/objects/OBJECT_HEADER_PROCESS_INFO.hh>
#include <introvirt/windows/kernel/nt/types/objects/OBJECT_HEADER_QUOTA_INFO.hh>

#include <introvirt/core/memory/GuestVirtualAddress.hh>
#include <introvirt/windows/kernel/nt/const/ObjectType.hh>

#include <introvirt/windows/kernel/nt/fwd.hh>

#include <cstdint>
#include <memory>

namespace introvirt {
namespace windows {
namespace nt {

/**
 * @brief Wrapper for the Windows OBJECT_HEADER structure
 *
 * Windows' kernel objects are prefixed with an OBJECT_HEADER. The HANDLE_TABLE stores references to
 * OBJECT_HEADERs, from which we can get the actual object.
 */
class OBJECT_HEADER {
  public:
    /**
     * @brief Get the index into the Type table
     */
    virtual uint8_t TypeIndex() const = 0;

    /**
     * @returns The guest address of the object that comes after the header
     */
    virtual GuestVirtualAddress Body() const = 0;

    /**
     * @brief Get the creator information
     *
     * @return The creator information
     * @throws InvalidMethodException if not available
     */
    virtual const OBJECT_HEADER_CREATOR_INFO& CreatorInfo() const = 0;

    /**
     * @brief Get the handle information
     *
     * @return The handle information
     * @throws InvalidMethodException if not available
     */
    virtual const OBJECT_HEADER_HANDLE_INFO& HandleInfo() const = 0;

    /**
     * @brief Get the name information
     *
     * @return The name information
     * @throws InvalidMethodException if not available
     */
    virtual const OBJECT_HEADER_NAME_INFO& NameInfo() const = 0;

    /**
     * @brief Get the process information
     *
     * @return The process information
     * @throws InvalidMethodException if not available
     */
    virtual const OBJECT_HEADER_PROCESS_INFO& ProcessInfo() const = 0;

    /**
     * @brief Get the quota information
     *
     * @return The quota information
     * @throws InvalidMethodException if not available
     */
    virtual const OBJECT_HEADER_QUOTA_INFO& QuotaInfo() const = 0;

    /**
     * @returns True if creator information is available
     */
    virtual bool has_creator_info() const = 0;

    /**
     * @returns True if handle information is available
     */
    virtual bool has_handle_info() const = 0;

    /**
     * @returns True if name information is available
     */
    virtual bool has_name_info() const = 0;

    /**
     * @returns True if process information is available
     */
    virtual bool has_process_info() const = 0;

    /**
     * @returns True if quota information is available
     */
    virtual bool has_quota_info() const = 0;

    /**
     * @returns The type of object being referred to
     */
    virtual ObjectType type() const = 0;

    /**
     * @returns The virtual address of the OBJECT_HEADER
     */
    virtual GuestVirtualAddress address() const = 0;

    static std::unique_ptr<OBJECT_HEADER> make_unique(const NtKernel& kernel,
                                                      const GuestVirtualAddress& gva);

    virtual ~OBJECT_HEADER() = default;
};

} /* namespace nt */
} /* namespace windows */
} /* namespace introvirt */
