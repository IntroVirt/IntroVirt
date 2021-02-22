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

#include <introvirt/windows/kernel/nt/types/objects/OBJECT_HEADER.hh>

#include "OBJECT_HEADER_CREATOR_INFO_IMPL.hh"
#include "OBJECT_HEADER_HANDLE_INFO_IMPL.hh"
#include "OBJECT_HEADER_NAME_INFO_IMPL.hh"
#include "OBJECT_HEADER_PROCESS_INFO_IMPL.hh"
#include "OBJECT_HEADER_QUOTA_INFO_IMPL.hh"

#include "windows/kernel/nt/structs/structs.hh"

#include <introvirt/windows/kernel/nt/types/objects/OBJECT_TYPE.hh>

#include <optional>

namespace introvirt {
namespace windows {
namespace nt {

template <typename PtrType>
class OBJECT_HEADER_IMPL final : public OBJECT_HEADER {
  public:
    /**
     * @brief Get the index into the Type table
     */
    uint8_t TypeIndex() const override;

    /**
     * @returns The guest address of the object that comes after the header
     */
    GuestVirtualAddress Body() const override;

    /**
     * @brief Get the creator information
     *
     * @return The creator information
     * @throws InvalidMethodException if not available
     */
    const OBJECT_HEADER_CREATOR_INFO& CreatorInfo() const override;

    /**
     * @brief Get the handle information
     *
     * @return The handle information
     * @throws InvalidMethodException if not available
     */
    const OBJECT_HEADER_HANDLE_INFO& HandleInfo() const override;

    /**
     * @brief Get the name information
     *
     * @return The name information
     * @throws InvalidMethodException if not available
     */
    const OBJECT_HEADER_NAME_INFO& NameInfo() const override;

    /**
     * @brief Get the process information
     *
     * @return The process information
     * @throws InvalidMethodException if not available
     */
    const OBJECT_HEADER_PROCESS_INFO& ProcessInfo() const override;

    /**
     * @brief Get the quota information
     *
     * @return The quota information
     * @throws InvalidMethodException if not available
     */
    const OBJECT_HEADER_QUOTA_INFO& QuotaInfo() const override;

    /**
     * @returns True if creator information is available
     */
    bool has_creator_info() const override;

    /**
     * @returns True if handle information is available
     */
    bool has_handle_info() const override;

    /**
     * @returns True if name information is available
     */
    bool has_name_info() const override;

    /**
     * @returns True if process information is available
     */
    bool has_process_info() const override;

    /**
     * @returns True if quota information is available
     */
    bool has_quota_info() const override;

    /**
     * @returns The type of object being referred to
     */
    ObjectType type() const override;

    /**
     * @returns The address of the OBJECT_HEADER
     */
    GuestVirtualAddress address() const override;

    OBJECT_HEADER_IMPL(const NtKernelImpl<PtrType>& kernel, const GuestVirtualAddress& gva);
    ~OBJECT_HEADER_IMPL() override = default;

  private:
    const NtKernelImpl<PtrType>& kernel_;
    const GuestVirtualAddress gva_;
    const structs::OBJECT_HEADER* offsets_;
    guest_ptr<char[]> buffer_;

    GuestVirtualAddress pcreator_info_;
    GuestVirtualAddress phandle_info_;
    GuestVirtualAddress pname_info_;
    GuestVirtualAddress pprocess_info_;
    GuestVirtualAddress pquota_info_;

    mutable std::optional<OBJECT_HEADER_CREATOR_INFO_IMPL<PtrType>> creator_info_;
    mutable std::optional<OBJECT_HEADER_HANDLE_INFO_IMPL<PtrType>> handle_info_;
    mutable std::optional<OBJECT_HEADER_NAME_INFO_IMPL<PtrType>> name_info_;
    mutable std::optional<OBJECT_HEADER_PROCESS_INFO_IMPL<PtrType>> process_info_;
    mutable std::optional<OBJECT_HEADER_QUOTA_INFO_IMPL<PtrType>> quota_info_;

    ObjectType type_;
    uint32_t TypeIndex_;
};

} // namespace nt
} // namespace windows
} // namespace introvirt