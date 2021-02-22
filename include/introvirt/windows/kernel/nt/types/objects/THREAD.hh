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

#include <introvirt/core/memory/GuestVirtualAddress.hh>
#include <introvirt/windows/kernel/nt/const/KTHREAD_STATE.hh>
#include <introvirt/windows/kernel/nt/fwd.hh>
#include <introvirt/windows/util/WindowsTime.hh>

#include <cstdint>
#include <memory>

namespace introvirt {
namespace windows {
namespace nt {

enum CT_FLAGS {
    CT_TERMINATED_BIT = 0x1,
    CT_DEAD_THREAD_BIT = 0x2,
    CT_HIDE_FROM_DEBUGGER_BIT = 0x4,
    CT_ACTIVE_IMPERSONATION_INFO_BIT = 0x8,
    CT_SYSTEM_THREAD_BIT = 0x10,
    CT_HARD_ERRORS_ARE_DISABLED_BIT = 0x20,
    CT_BREAK_ON_TERMINATION_BIT = 0x40,
    CT_SKIP_CREATION_MSG_BIT = 0x80,
    CT_SKIP_TERMINATION_MSG_BIT = 0x100,
    CT_INDIRECT_CPU_SETS = 0x00020000,
    CT_DISABLE_DYNAMIC_CODE_OPT_OUT = 0x00040000,
};

/**
 * This class handles the Windows KTHREAD/ETHREAD structures
 */
class THREAD : public DISPATCHER_OBJECT {
  public:
    class CrossThreadFlags {
      public:
        //
        // Cross Thread Flags
        //
        bool CT_TERMINATED_BIT() const;
        bool CT_DEAD_THREAD_BIT() const;
        bool CT_HIDE_FROM_DEBUGGER_BIT() const;
        bool CT_ACTIVE_IMPERSONATION_INFO_BIT() const;
        bool CT_SYSTEM_THREAD_BIT() const;
        bool CT_HARD_ERRORS_ARE_DISABLED_BIT() const;
        bool CT_BREAK_ON_TERMINATION_BIT() const;
        bool CT_SKIP_CREATION_MSG_BIT() const;
        bool CT_SKIP_TERMINATION_MSG_BIT() const;
        bool CT_INDIRECT_CPU_SETS() const;
        bool CT_DISABLE_DYNAMIC_CODE_OPT_OUT() const;
        uint32_t value() const;

        CrossThreadFlags(uint32_t value) : value_(value) {}

      private:
        uint32_t value_;
    };

    /**
     * @returns The thread environment block
     */
    virtual TEB* Teb() = 0;
    virtual const TEB* Teb() const = 0;

    /**
     * @brief Get the PID/TID for this THREAD
     */
    virtual const CLIENT_ID& Cid() const = 0;

    /**
     * @returns The PROCESS object that owns this thread, or NULL if unavailable
     */
    virtual const PROCESS& Process() const = 0;
    virtual PROCESS& Process() = 0;

    virtual int8_t BasePriority() const = 0;
    virtual void BasePriority(int8_t priority) = 0;

    virtual int8_t Priority() const = 0;
    virtual void Priority(int8_t priority) = 0;

    virtual uint64_t Affinity() const = 0;
    virtual void Affinity(uint64_t affinity) = 0;

    virtual uint64_t UserAffinity() const = 0;
    virtual void UserAffinity(uint64_t affinity) = 0;

    virtual uint32_t IdealProcessor() const = 0;
    virtual void IdealProcessor(uint32_t processor) = 0;

    virtual uint32_t UserIdealProcessor() const = 0;
    virtual void UserIdealProcessor(uint32_t processor) = 0;

    virtual int16_t KernelApcDisable() const = 0;
    virtual void KernelApcDisable(int16_t value) = 0;

    virtual int16_t SpecialApcDisable() const = 0;
    virtual void SpecialApcDisable(int16_t value) = 0;

    virtual uint8_t PreviousMode() const = 0;
    virtual void PreviousMode(uint8_t mode) = 0;

    /**
     * @returns The Win32StartAddress member of ETHREAD
     */
    virtual GuestVirtualAddress Win32StartAddress() const = 0;

    /*
     * Retrieve the state of the thread
     *
     * @returns A value in the KTHREAD_STATE enum
     */
    virtual KTHREAD_STATE State() const = 0;

    /*
     *  the state of the thread (dangerous)
     *
     * @param State A value from the KTHREAD_STATE enum
     */
    virtual void State(KTHREAD_STATE State) = 0;

    virtual bool Preempted() const = 0;

    virtual void Preempted(bool Preempted) = 0;

    /**
     * @returns A bitmask of CT_* flags
     */
    virtual uint32_t CrossThreadFlags() const = 0;

    /*
     * @param CrossThreadFlags A bitmask of CT_* flags
     */
    virtual void CrossThreadFlags(uint32_t CrossThreadFlags) = 0;

    virtual int8_t Saturation() const = 0;
    virtual void Saturation(int8_t saturation) = 0;

    virtual bool DisableDynamicCodeOptOut() const = 0;

    virtual void DisableDynamicCodeOptOut(bool DisableDynamicCodeOptOut) = 0;

    virtual uint64_t InitialStack() const = 0;
    virtual uint64_t StackBase() const = 0;
    virtual uint64_t StackLimit() const = 0;
    virtual uint64_t KernelStack() const = 0;

    virtual WindowsTime CreateTime() const = 0;
    virtual void CreateTime(const WindowsTime& time) = 0;

    static std::shared_ptr<THREAD> make_shared(const NtKernel& kernel,
                                               const GuestVirtualAddress& gva);
    static std::shared_ptr<THREAD> make_shared(const NtKernel& kernel,
                                               std::unique_ptr<OBJECT_HEADER>&& header);
};

} /* namespace nt */
} /* namespace windows */
} /* namespace introvirt */
