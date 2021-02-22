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

#include <introvirt/fwd.hh>

#include <cstdint>
#include <string>

namespace introvirt {
namespace windows {
namespace nt {

class KDDEBUGGER_DATA64 {
  public:
    /**
     * @returns The base address of the Windows kernel
     */
    virtual uint64_t KernelBase() const = 0;

    /**
     * @returns The service pack number of the operating system
     */
    virtual uint32_t ServicePackNumber() const = 0;

    /**
     * @returns The address of PsLoadedModuleList, which lists loaded kernel modules
     */
    virtual uint64_t PsLoadedModuleList() const = 0;

    /**
     * @returns The address of the active process list head
     */
    virtual uint64_t PsActiveProcessHead() const = 0;

    /**
     * @returns The NT build string
     */
    virtual const std::string& NtBuildLab() const = 0;

    /**
     * @returns The address of the KiProcessorBlock array
     */
    virtual uint64_t KiProcessorBlock() const = 0;

    /**
     * @returns The root of the OBJECT_TYPE list
     */
    virtual uint64_t ObpTypeObjectType() const = 0;

    /**
     * @returns The root directory object
     */
    virtual uint64_t ObpRootDirectoryObject() const = 0;

    /**
     * @returns The size of the ETHREAD structure
     */
    virtual uint16_t SizeEThread() const = 0;

    /**
     * @returns The address of the PspCidTable
     */
    virtual uint64_t PspCidTable() const = 0;

    /**
     * @returns True if the kernel has PAE enabled
     */
    virtual bool PaeEnabled() const = 0;

    virtual ~KDDEBUGGER_DATA64() = default;
};

} /* namespace nt */
} /* namespace windows */
} /* namespace introvirt */
