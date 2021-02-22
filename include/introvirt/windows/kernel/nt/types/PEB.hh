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
#include <introvirt/windows/kernel/nt/fwd.hh>

#include <cstdint>
#include <memory>

namespace introvirt {
namespace windows {
namespace nt {

/**
 * Parser for the Windows Process Environment Block (PEB)
 */
class PEB {
  public:
    /**
     * @returns The base address of the executable image
     */
    virtual GuestVirtualAddress ImageBaseAddress() const = 0;

    /**
     * @returns The PEB_LDR_DATA, containing information about loaded libraries and the exe itself
     */
    virtual const PEB_LDR_DATA* Ldr() const = 0;
    virtual PEB_LDR_DATA* Ldr() = 0;

    /**
     * @return Information about the process environment
     */
    virtual const RTL_USER_PROCESS_PARAMETERS* ProcessParameters() const = 0;
    virtual RTL_USER_PROCESS_PARAMETERS* ProcessParameters() = 0;

    /**
     * @returns The major version of the OS
     */
    virtual uint32_t OSMajorVersion() const = 0;

    /**
     * @returns The minor version of the OS
     */
    virtual uint32_t OSMinorVersion() const = 0;

    /**
     * @returns The build number of the OS
     */
    virtual uint16_t OSBuildNumber() const = 0;

    /**
     * @returns The CSD version of the OS, containing service pack information
     */
    virtual uint16_t OSCSDVersion() const = 0;

    /**
     * @returns The platform ID of the OS
     */
    virtual uint32_t OSPlatformId() const = 0;

    /**
     * @returns The service pack number of the OS
     */
    virtual uint16_t ServicePackNumber() const = 0;

    /**
     * @returns The minor service pack number of the OS
     */
    virtual uint16_t MinorServicePackNumber() const = 0;

    /**
     * @returns The number of physical processors
     */
    virtual uint32_t NumberOfProcessors() const = 0;

    /**
     * @returns The virtual address of the PEB in-guest
     */
    virtual GuestVirtualAddress address() const = 0;

    /**
     * @returns The value of the BeingDebugged field
     */
    virtual bool BeingDebugged() const = 0;

    /**
     * @returns The value of the BeingDebugged field
     */
    virtual void BeingDebugged(bool BeingDebugged) = 0;

    virtual ~PEB() = default;
};

} /* namespace nt */
} /* namespace windows */
} /* namespace introvirt */
