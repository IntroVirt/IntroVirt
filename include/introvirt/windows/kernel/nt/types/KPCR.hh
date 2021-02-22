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

#include <introvirt/core/fwd.hh>
#include <introvirt/windows/kernel/nt/fwd.hh>

#include <memory>

namespace introvirt {
namespace windows {
namespace nt {

/**
 * @brief The KPCR (Kernel Processor Control Region) is used by Windows to hold information about
 * the current thread.
 *
 */
class KPCR {
  public:
    /**
     * @brief Get the process ID of the current thread
     *
     * @return The current process id
     */
    virtual uint64_t pid() const = 0;

    /**
     * @brief Get the thread ID of the current thread
     *
     * @return The current thread id
     */
    virtual uint64_t tid() const = 0;

    /**
     * @brief Get the name of the current process
     *
     * @return The current process name
     */
    virtual std::string process_name() const = 0;

    /**
     * @brief Get the currently active thread
     *
     * @return The current active thread on this processor
     * @throws IdleThreadException If the CurrentThread is Idle
     */
    virtual THREAD& CurrentThread() = 0;

    /**
     * @copydoc KPCR::CurrentThread()
     */
    virtual const THREAD& CurrentThread() const = 0;

    /**
     * @brief Get the paging table used by the kernel, if the field exists.
     *
     * This field is used for Spectre/Meltdown mitigation.
     *
     * @return The KernelDirectoryTableBase value, if one exists. Null otherwise.
     */
    virtual uint64_t KernelDirectoryTableBase() const = 0;

    /**
     * @brief Check if the processor for this KPCR is idle
     *
     * @return true If the processor is idle
     * @return false If the processor is not idle
     */
    virtual bool idle() const = 0;

    /**
     * @brief Reset the state held by the KPCR
     *
     * This is used internally to reset the cached objects held by the KPCR.
     * When a new event is delivered, the KPCR is reset, releasing the cached
     * CurrentThread object, as well as other state.
     */
    virtual void reset() = 0;

    /**
     * @brief Destroy the instance
     */
    virtual ~KPCR() = default;
};

} // namespace nt
} // namespace windows
} // namespace introvirt