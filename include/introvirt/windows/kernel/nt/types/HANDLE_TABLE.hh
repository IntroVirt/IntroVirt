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

#include <introvirt/windows/kernel/nt/types/access_mask/ACCESS_MASK.hh>

#include <introvirt/core/fwd.hh>
#include <introvirt/windows/kernel/nt/fwd.hh>

#include <cstdint>
#include <memory>
#include <vector>

namespace introvirt {
namespace windows {
namespace nt {

/**
 * Window's uses handle tables to store references to kernel objects
 */
class HANDLE_TABLE {
  public:
    /**
     * Lookup a handle by number
     *
     * @param handle A handle number to retrieve
     *
     * @returns A HANDLE_TABLE_ENTRY value. Can be used to create an OBJECT_HEADER.
     */
    virtual std::unique_ptr<const HANDLE_TABLE_ENTRY> Handle(uint64_t handle) const = 0;
    virtual std::unique_ptr<HANDLE_TABLE_ENTRY> Handle(uint64_t handle) = 0;

    /**
     * Lookup a DEVICE_OBJECT by handle number
     *
     * @returns The DEVICE_OBJECT, or nullptr if the handle was invalid.
     */
    virtual std::shared_ptr<const DEVICE_OBJECT> DeviceObject(uint64_t handle) const = 0;
    virtual std::shared_ptr<DEVICE_OBJECT> DeviceObject(uint64_t handle) = 0;

    /**
     * Lookup an OBJECT_DIRECTORY by handle number
     *
     * @returns The OBJECT_DIRECTORY, or nullptr if the handle was invalid.
     */
    virtual std::shared_ptr<const OBJECT_DIRECTORY> DirectoryObject(uint64_t handle) const = 0;
    virtual std::shared_ptr<OBJECT_DIRECTORY> DirectoryObject(uint64_t handle) = 0;

    /**
     * Lookup a DRIVER_OBJECT by handle number
     *
     * @returns The DRIVER_OBJECT, or nullptr if the handle was invalid.
     */
    virtual std::shared_ptr<const DRIVER_OBJECT> DriverObject(uint64_t handle) const = 0;
    virtual std::shared_ptr<DRIVER_OBJECT> DriverObject(uint64_t handle) = 0;

    /**
     * Lookup a KEVENT by handle number
     *
     * @returns The KEVENT, or nullptr if the handle was invalid.
     */
    virtual std::shared_ptr<const KEVENT> EventObject(uint64_t handle) const = 0;
    virtual std::shared_ptr<KEVENT> EventObject(uint64_t handle) = 0;

    /**
     * Lookup a FILE_OBJECT by handle number
     *
     * @returns The FILE_OBJECT, or nullptr if the handle was invalid.
     */
    virtual std::shared_ptr<const FILE_OBJECT> FileObject(uint64_t handle) const = 0;
    virtual std::shared_ptr<FILE_OBJECT> FileObject(uint64_t handle) = 0;

    /**
     * Lookup a CM_KEY_BODY by handle number
     *
     * @returns The CM_KEY_BODY, or nullptr if the handle was invalid.
     */
    virtual std::shared_ptr<const CM_KEY_BODY> KeyObject(uint64_t handle) const = 0;
    virtual std::shared_ptr<CM_KEY_BODY> KeyObject(uint64_t handle) = 0;

    /**
     * Lookup a PROCESS by handle number
     *
     * @returns The PROCESS, or nullptr if the handle was invalid.
     */
    virtual std::shared_ptr<const PROCESS> ProcessObject(uint64_t handle) const = 0;
    virtual std::shared_ptr<PROCESS> ProcessObject(uint64_t handle) = 0;

    /**
     * Lookup an SECTION by handle number
     *
     * @returns The SECTION, or nullptr if the handle was invalid.
     */
    virtual std::shared_ptr<const SECTION> SectionObject(uint64_t handle) const = 0;
    virtual std::shared_ptr<SECTION> SectionObject(uint64_t handle) = 0;

    /**
     * Lookup an OBJECT_SYMBOLIC_LINK by handle number
     *
     * @returns The OBJECT_SYMBOLIC_LINK, or nullptr if the handle was invalid.
     */
    virtual std::shared_ptr<const OBJECT_SYMBOLIC_LINK>
    SymbolicLinkObject(uint64_t handle) const = 0;
    virtual std::shared_ptr<OBJECT_SYMBOLIC_LINK> SymbolicLinkObject(uint64_t handle) = 0;

    /**
     * Lookup a THREAD by handle number
     *
     * @returns The THREAD, or nullptr if the handle was invalid.
     */
    virtual std::shared_ptr<const THREAD> ThreadObject(uint64_t handle) const = 0;
    virtual std::shared_ptr<THREAD> ThreadObject(uint64_t handle) = 0;

    /**
     * Lookup a TOKEN by handle number
     *
     * @returns The TOKEN, or nullptr if the handle was invalid.
     */
    virtual std::shared_ptr<const TOKEN> TokenObject(uint64_t handle) const = 0;
    virtual std::shared_ptr<TOKEN> TokenObject(uint64_t handle) = 0;

    /**
     * Lookup an OBJECT_TYPE by handle number
     *
     * @returns The OBJECT_TYPE, or nullptr if the handle was invalid.
     */
    virtual std::shared_ptr<const OBJECT_TYPE> TypeObject(uint64_t handle) const = 0;
    virtual std::shared_ptr<OBJECT_TYPE> TypeObject(uint64_t handle) = 0;

    /**
     * Lookup an object by handle number
     *
     * @param handle A handle number to retrieve
     *
     * @returns A pointer to an OBJECT object. Do not delete.
     */
    virtual std::shared_ptr<const OBJECT> Object(uint64_t handle) const = 0;
    virtual std::shared_ptr<OBJECT> Object(uint64_t handle) = 0;

    /** @returns The list of open handles. */
    virtual std::vector<std::unique_ptr<const HANDLE_TABLE_ENTRY>> open_handles() const = 0;

    /** @returns The number of open handles. */
    virtual int32_t HandleCount() const = 0;

    /**
     * @return The next handle that would require additional memory allocation
     */
    virtual uint32_t NextHandleNeedingPool() const = 0;

    virtual ~HANDLE_TABLE() = default;
};

} /* namespace nt */
} /* namespace windows */
} /* namespace introvirt */
