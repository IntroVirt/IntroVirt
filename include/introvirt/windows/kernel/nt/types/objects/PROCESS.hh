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

#include "DISPATCHER_OBJECT.hh"
#include "OBJECT_HEADER.hh"

#include <introvirt/windows/kernel/nt/fwd.hh>
#include <introvirt/windows/util/WindowsTime.hh>

#include <memory>
#include <string>
#include <vector>

namespace introvirt {
namespace windows {
namespace nt {

class PROCESS : public DISPATCHER_OBJECT {
  public:
    /**
     *  the Process Environment Block (PEB) for this process.
     * The PEB contains information about loaded modules and the process image itself.
     *
     * @returns The Process Environment Block for this process
     */
    virtual const PEB* Peb() const = 0;
    virtual PEB* Peb() = 0;

    /**
     * If this process is a Wow64 process, return the 32-bit version of the PEB.
     *
     * @returns The 32-bit PEB, or NULL if not available.
     */
    virtual const PEB* WoW64Process() const = 0;
    virtual PEB* WoW64Process() = 0;

    /**
     * ImageFileName is a field in the EPROCESS structure which has a short name for the process.
     *
     * @returns The ImageFileName string associated with this process.
     */
    virtual const std::string& ImageFileName() const = 0;
    virtual void ImageFileName(const std::string& value) = 0;

    /**
     * @brief Get the full path of the image.
     *
     * There isn't a simple field to retreive this value. The operation is expensive, but cached.
     *
     * @return The full path to the executable ("c:\windows\system32\notepad.exe")
     */
    virtual const std::string& full_path() const = 0;

    /**
     * @brief Get the handle table for this process, used for looking up objects by handle number
     *
     * @returns The handle table for this process
     *
     * @throws InvalidStructureException If the HANDLE_TABLE is null
     */
    virtual std::unique_ptr<HANDLE_TABLE> ObjectTable() = 0;

    /**
     * @copydoc PROCESS::ObjectTable()
     */
    virtual std::unique_ptr<const HANDLE_TABLE> ObjectTable() const = 0;

    /**
     * @returns The unique process ID associated with this process
     */
    virtual uint64_t UniqueProcessId() const = 0;

    /**
     * @returns The unique process ID of this process' parent
     */
    virtual uint64_t InheritedFromUniqueProcessId() const = 0;
    virtual void InheritedFromUniqueProcessId(uint64_t pid) = 0;

    virtual std::shared_ptr<const MMVAD> VadRoot() const = 0;

    virtual TOKEN& Token() = 0;
    virtual const TOKEN& Token() const = 0;

    virtual uint64_t DirectoryTableBase() const = 0;

    virtual uint64_t UserDirectoryTableBase() const = 0;

    virtual uint32_t Cookie() const = 0;

    virtual uint64_t SectionBaseAddress() const = 0;

    /**
     * @returns A vector of threads belonging to this process
     */
    virtual std::vector<std::shared_ptr<THREAD>> ThreadList() = 0;
    virtual std::vector<std::shared_ptr<const THREAD>> ThreadList() const = 0;

    /**
     * @returns A session information object
     */
    virtual const MM_SESSION_SPACE* Session() const = 0;

    /**
     * @returns True if this is a 32-bit process running on 64-bit Windows
     */
    virtual bool isWow64Process() const = 0;

    virtual bool DisableDynamicCode() const = 0;

    virtual void DisableDynamicCode(bool DisableDynamicCode) = 0;

    virtual bool DisableDynamicCodeAllowOptOut() const = 0;
    virtual void DisableDynamicCodeAllowOptOut(bool DisableDynamicCodeAllowOptOut) = 0;

    virtual uint32_t ModifiedPageCount() const = 0;
    virtual void ModifiedPageCount(uint32_t ModifiedPageCount) = 0;

    virtual WindowsTime CreateTime() const = 0;
    virtual void CreateTime(const WindowsTime& time) = 0;

    virtual uint64_t MinimumWorkingSetSize() const = 0;
    virtual void MinimumWorkingSetSize(uint64_t MinimumWorkingSetSize) = 0;

    virtual uint64_t MaximumWorkingSetSize() const = 0;
    virtual void MaximumWorkingSetSize(uint64_t MaximumWorkingSetSize) = 0;

    virtual uint8_t ProtectionLevel() const = 0;
    virtual void ProtectionLevel(uint8_t Level) = 0;

    /**
     * @brief Get the Win32Process pointer
     *
     * @return The Win32Process pointer from the EPROCESS structure
     */
    virtual GuestVirtualAddress Win32Process() const = 0;

    virtual ~PROCESS() = default;

    static std::shared_ptr<PROCESS> make_shared(const NtKernel& kernel,
                                                const GuestVirtualAddress& gva);
    static std::shared_ptr<PROCESS> make_shared(const NtKernel& kernel,
                                                std::unique_ptr<OBJECT_HEADER>&& header);
};

} /* namespace nt */
} /* namespace windows */
} /* namespace introvirt */
