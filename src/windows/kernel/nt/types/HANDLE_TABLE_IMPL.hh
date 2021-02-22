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

#include "windows/kernel/nt/structs/structs.hh"

#include <introvirt/core/memory/guest_ptr.hh>
#include <introvirt/windows/kernel/nt/types/HANDLE_TABLE.hh>

namespace introvirt {
namespace windows {
namespace nt {

template <typename PtrType>
class NtKernelImpl;

template <typename PtrType>
class HANDLE_TABLE_IMPL final : public HANDLE_TABLE {
  public:
    std::unique_ptr<const HANDLE_TABLE_ENTRY> Handle(uint64_t handle) const override;
    std::unique_ptr<HANDLE_TABLE_ENTRY> Handle(uint64_t handle) override;

    std::shared_ptr<const DEVICE_OBJECT> DeviceObject(uint64_t handle) const override;
    std::shared_ptr<DEVICE_OBJECT> DeviceObject(uint64_t handle) override;

    std::shared_ptr<const OBJECT_DIRECTORY> DirectoryObject(uint64_t handle) const override;
    std::shared_ptr<OBJECT_DIRECTORY> DirectoryObject(uint64_t handle) override;

    std::shared_ptr<const DRIVER_OBJECT> DriverObject(uint64_t handle) const override;
    std::shared_ptr<DRIVER_OBJECT> DriverObject(uint64_t handle) override;

    std::shared_ptr<const KEVENT> EventObject(uint64_t handle) const override;
    std::shared_ptr<KEVENT> EventObject(uint64_t handle) override;

    std::shared_ptr<const FILE_OBJECT> FileObject(uint64_t handle) const override;
    std::shared_ptr<FILE_OBJECT> FileObject(uint64_t handle) override;

    std::shared_ptr<const CM_KEY_BODY> KeyObject(uint64_t handle) const override;
    std::shared_ptr<CM_KEY_BODY> KeyObject(uint64_t handle) override;

    std::shared_ptr<const PROCESS> ProcessObject(uint64_t handle) const override;
    std::shared_ptr<PROCESS> ProcessObject(uint64_t handle) override;

    std::shared_ptr<const SECTION> SectionObject(uint64_t handle) const override;
    std::shared_ptr<SECTION> SectionObject(uint64_t handle) override;

    std::shared_ptr<const OBJECT_SYMBOLIC_LINK> SymbolicLinkObject(uint64_t handle) const override;
    std::shared_ptr<OBJECT_SYMBOLIC_LINK> SymbolicLinkObject(uint64_t handle) override;

    std::shared_ptr<const THREAD> ThreadObject(uint64_t handle) const override;
    std::shared_ptr<THREAD> ThreadObject(uint64_t handle) override;

    std::shared_ptr<const TOKEN> TokenObject(uint64_t handle) const override;
    std::shared_ptr<TOKEN> TokenObject(uint64_t handle) override;

    std::shared_ptr<const OBJECT_TYPE> TypeObject(uint64_t handle) const override;
    std::shared_ptr<OBJECT_TYPE> TypeObject(uint64_t handle) override;

    std::shared_ptr<const OBJECT> Object(uint64_t handle) const override;
    std::shared_ptr<OBJECT> Object(uint64_t handle) override;

    std::vector<std::unique_ptr<const HANDLE_TABLE_ENTRY>> open_handles() const override;

    int32_t HandleCount() const override;

    uint32_t NextHandleNeedingPool() const override;

    HANDLE_TABLE_IMPL(const NtKernelImpl<PtrType>& kernel, const GuestVirtualAddress& gva,
                      bool isCidTable = false);

    ~HANDLE_TABLE_IMPL() override;

  private:
    void
    parse_open_handles_l2(GuestVirtualAddress TableAddress,
                          std::vector<std::unique_ptr<const HANDLE_TABLE_ENTRY>>& handles) const;

    void parse_open_handles_l1(GuestVirtualAddress TableAddress,
                               std::vector<std::unique_ptr<const HANDLE_TABLE_ENTRY>>& handles,
                               PtrType handle_start = 0) const;

    void parse_open_handles_l0(GuestVirtualAddress TableAddress,
                               std::vector<std::unique_ptr<const HANDLE_TABLE_ENTRY>>& handles,
                               PtrType handle_start = 0) const;

    template <typename T, ObjectType ObjectType>
    std::shared_ptr<T> ObjectByType(uint64_t handle);

  private:
    using ObjectTable = std::map<uint64_t, std::unique_ptr<OBJECT>>;

    const NtKernelImpl<PtrType>& kernel_;
    const GuestVirtualAddress gva_;
    const structs::HANDLE_TABLE* const offsets_;
    const structs::HANDLE_TABLE_ENTRY* const handle_table_entry_;
    const bool isPspCidTable;

    guest_ptr<char[]> buffer_;
};

} // namespace nt
} // namespace windows
} // namespace introvirt