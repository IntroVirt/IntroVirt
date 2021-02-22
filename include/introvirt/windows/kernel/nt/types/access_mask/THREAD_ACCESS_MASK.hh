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
 * @brief Valid flags for THREAD_ACCESS_MASK
 *
 * <a
 * href="https://docs.microsoft.com/en-us/windows/win32/procthread/thread-security-and-access-rights">MSDN
 * Article</a>
 *
 * @see THREAD_ACCESS_MASK
 */
enum ThreadAccessMaskFlag {
    /// Required to terminate a thread using TerminateThread.
    THREAD_TERMINATE = 0x001,
    /// Required to suspend or resume a thread
    THREAD_SUSPEND_RESUME = 0x002,
    /// Required to read the context of a thread using GetThreadContext.
    THREAD_GET_CONTEXT = 0x008,
    /// Required to write the context of a thread using SetThreadContext.
    THREAD_SET_CONTEXT = 0x010,
    /// Required to set certain information in the thread object.
    THREAD_SET_INFORMATION = 0x020,
    /// Required to read certain information from the thread object, such as the exit code
    THREAD_QUERY_INFORMATION = 0x040,
    /// Required to set the impersonation token for a thread using SetThreadToken.
    THREAD_SET_THREAD_TOKEN = 0x080,
    /// Required to use a thread's security information directly without calling it by using a
    /// communication mechanism that provides impersonation services.
    THREAD_IMPERSONATE = 0x100,
    /// Required for a server thread that impersonates a client.
    THREAD_DIRECT_IMPERSONATION = 0x200,
    /// Required to set certain information in the thread object. A handle that has the
    /// THREAD_SET_INFORMATION access right is automatically granted THREAD_SET_LIMITED_INFORMATION.
    THREAD_SET_LIMITED_INFORMATION = 0x400,
    /// Required to read certain information from the thread objects (see GetProcessIdOfThread).
    THREAD_QUERY_LIMITED_INFORMATION = 0x800,
    /// All possible access rights for a thread object.
    THREAD_ALL_ACCESS = (STANDARD_RIGHTS_REQUIRED | SYNCHRONIZE | 0x3FF),
};

/**
 * @brief ACCESS_MASK class for thread permissions
 *
 * @see ThreadAccessMaskFlag
 */
class THREAD_ACCESS_MASK final : public ACCESS_MASK {
  public:
    /**
     * @brief Check if the given flag is enabled
     *
     * @param flag
     * @return true
     * @return false
     */
    bool has(ThreadAccessMaskFlag flag) const { return (value() & flag) == flag; }

    /**
     * @brief Set the state of the given flag to enabled
     *
     * @param flag The flag to enable
     */
    void set(ThreadAccessMaskFlag flag) { value(value() | flag); }

    /**
     * @brief Clear the given flag
     *
     * @param flag The flag to clear
     */
    void clear(ThreadAccessMaskFlag flag) { value(value() & ~flag); }

    AccessMaskType type() const override { return ThreadAccessMask; }

    // Constructors and assignment operators
    THREAD_ACCESS_MASK() = default;
    THREAD_ACCESS_MASK(uint32_t mask) : ACCESS_MASK(mask) {}

    THREAD_ACCESS_MASK(const THREAD_ACCESS_MASK&) = default;
    THREAD_ACCESS_MASK& operator=(const THREAD_ACCESS_MASK&) = default;
};

const std::string& to_string(ThreadAccessMaskFlag);
std::ostream& operator<<(std::ostream&, ThreadAccessMaskFlag);

std::string to_string(THREAD_ACCESS_MASK);
std::ostream& operator<<(std::ostream&, THREAD_ACCESS_MASK);

} /* namespace nt */
} /* namespace windows */
} /* namespace introvirt */
