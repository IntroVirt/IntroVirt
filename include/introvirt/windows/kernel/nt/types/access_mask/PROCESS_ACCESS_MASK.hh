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

#include "ACCESS_MASK.hh"

namespace introvirt {
namespace windows {
namespace nt {

/**
 * @brief Valid flags for PROCESS_ACCESS_MASK
 *
 * <a
 * href="https://docs.microsoft.com/en-us/windows/win32/procthread/process-security-and-access-rights">MSDN
 * Article</a>
 *
 * @see PROCESS_ACCESS_MASK
 */
enum ProcessAccessMaskFlag {
    /// Required to terminate a process using TerminateProcess.
    PROCESS_TERMINATE = 0x001,
    /// Required to create a thread.
    PROCESS_CREATE_THREAD = 0x002,
    /// Required to perform an operation on the address space of a process.
    PROCESS_VM_OPERATION = 0x008,
    /// Required to read memory in a process using ReadProcessMemory.
    PROCESS_VM_READ = 0x010,
    ///  	Required to write to memory in a process using WriteProcessMemory.
    PROCESS_VM_WRITE = 0x020,
    /// Required to duplicate a handle using DuplicateHandle.
    PROCESS_DUP_HANDLE = 0x040,
    /// Required to create a process.
    PROCESS_CREATE_PROCESS = 0x080,
    /// Required to set memory limits using SetProcessWorkingSetSize.
    PROCESS_SET_QUOTA = 0x100,
    /// Required to set certain information about a process, such as its priority class
    PROCESS_SET_INFORMATION = 0x200,
    /// Required to retrieve certain information about a process, such as its token, exit code, and
    /// priority class.
    PROCESS_QUERY_INFORMATION = 0x400,
    /// Required to suspend or resume a process.
    PROCESS_SUSPEND_RESUME = 0x800,

    /// Required to retrieve certain information about a process. A handle that has the
    /// PROCESS_QUERY_INFORMATION access right is automatically granted
    /// PROCESS_QUERY_LIMITED_INFORMATION.
    PROCESS_QUERY_LIMITED_INFORMATION = 0x1000,

    /// All possible access rights for a process object
    PROCESS_ALL_ACCESS = (0x000F0000L | 0x00100000L | 0xFFF),
};

/**
 * @brief ACCESS_MASK class for process permissions
 *
 * @see ProcessAccessMaskFlag
 */
class PROCESS_ACCESS_MASK final : public ACCESS_MASK {
  public:
    /**
     * @brief Check if the given flag is enabled
     *
     * @param flag
     * @return true
     * @return false
     */
    bool has(ProcessAccessMaskFlag flag) const { return (value() & flag) == flag; }

    /**
     * @brief Set the state of the given flag to enabled
     *
     * @param flag The flag to enable
     */
    void set(ProcessAccessMaskFlag flag) { value(value() | flag); }

    /**
     * @brief Clear the given flag
     *
     * @param flag The flag to clear
     */
    void clear(ProcessAccessMaskFlag flag) { value(value() & ~flag); }

    AccessMaskType type() const override { return ProcessAccessMask; }

    // Constructors and assignment operators
    PROCESS_ACCESS_MASK() = default;
    PROCESS_ACCESS_MASK(uint32_t mask) : ACCESS_MASK(mask) {}

    PROCESS_ACCESS_MASK(const PROCESS_ACCESS_MASK&) = default;
    PROCESS_ACCESS_MASK& operator=(const PROCESS_ACCESS_MASK&) = default;
};

const std::string& to_string(ProcessAccessMaskFlag);
std::ostream& operator<<(std::ostream&, ProcessAccessMaskFlag);

std::string to_string(PROCESS_ACCESS_MASK);
std::ostream& operator<<(std::ostream&, PROCESS_ACCESS_MASK);

} /* namespace nt */
} /* namespace windows */
} /* namespace introvirt */
