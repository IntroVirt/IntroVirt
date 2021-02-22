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

#include "DISPATCHER_OBJECT_IMPL.hh"
#include "windows/kernel/nt/structs/structs.hh"
#include "windows/kernel/nt/types/CLIENT_ID_IMPL.hh"
#include "windows/kernel/nt/types/TEB_IMPL.hh"

#include <introvirt/windows/kernel/nt/types/TEB.hh>
#include <introvirt/windows/kernel/nt/types/objects/THREAD.hh>

#include <introvirt/core/memory/guest_ptr.hh>
#include <introvirt/fwd.hh>

#include <memory>
#include <optional>

namespace introvirt {
namespace windows {
namespace nt {

template <typename PtrType>
class THREAD_IMPL final : public DISPATCHER_OBJECT_IMPL<PtrType, THREAD> {
  public:
    /**
     * @returns The thread environment block
     */
    TEB* Teb() override;
    const TEB* Teb() const override;

    /**
     * @brief Get the PID/TID for this THREAD
     */
    const CLIENT_ID& Cid() const override;

    /**
     * @returns The PROCESS object that owns this thread, or NULL if unavailable
     */
    const PROCESS& Process() const override;
    PROCESS& Process() override;

    int8_t BasePriority() const override;
    void BasePriority(int8_t priority) override;

    int8_t Priority() const override;
    void Priority(int8_t priority) override;

    uint64_t Affinity() const override;
    void Affinity(uint64_t affinity) override;

    uint64_t UserAffinity() const override;
    void UserAffinity(uint64_t affinity) override;

    uint32_t IdealProcessor() const override;
    void IdealProcessor(uint32_t processor) override;

    uint32_t UserIdealProcessor() const override;
    void UserIdealProcessor(uint32_t processor) override;

    int16_t KernelApcDisable() const override;
    void KernelApcDisable(int16_t value) override;

    int16_t SpecialApcDisable() const override;
    void SpecialApcDisable(int16_t value) override;

    uint8_t PreviousMode() const override;
    void PreviousMode(uint8_t mode) override;

    /**
     * @returns The Win32StartAddress member of ETHREAD
     */
    GuestVirtualAddress Win32StartAddress() const override;

    /*
     * Retrieve the state of the thread
     *
     * @returns A value in the KTHREAD_STATE enum
     */
    KTHREAD_STATE State() const override;

    /*
     *  the state of the thread (dangerous)
     *
     * @param State A value from the KTHREAD_STATE enum
     */
    void State(KTHREAD_STATE State) override;

    bool Preempted() const override;

    void Preempted(bool Preempted) override;

    /**
     * @returns A bitmask of CT_* flags
     */
    uint32_t CrossThreadFlags() const override;

    /*
     * @param CrossThreadFlags A bitmask of CT_* flags
     */
    void CrossThreadFlags(uint32_t CrossThreadFlags) override;

    int8_t Saturation() const override;
    void Saturation(int8_t saturation) override;

    bool DisableDynamicCodeOptOut() const override;
    void DisableDynamicCodeOptOut(bool DisableDynamicCodeOptOut) override;

    uint64_t InitialStack() const override;
    uint64_t StackBase() const override;
    uint64_t StackLimit() const override;
    uint64_t KernelStack() const override;

    WindowsTime CreateTime() const override;
    void CreateTime(const WindowsTime& time) override;

    THREAD_IMPL(const NtKernelImpl<PtrType>& kernel, const GuestVirtualAddress& gva);
    THREAD_IMPL(const NtKernelImpl<PtrType>& kernel,
                std::unique_ptr<OBJECT_HEADER_IMPL<PtrType>>&& object_header);

  private:
    const NtKernelImpl<PtrType>& kernel_;
    const structs::ETHREAD* offsets_;
    CLIENT_ID_IMPL<PtrType> Cid_;
    guest_ptr<char[]> buffer_;

    mutable std::recursive_mutex mtx_;
    mutable std::shared_ptr<PROCESS> Process_;
    mutable std::optional<TEB_IMPL<PtrType>> Teb_;
};

} // namespace nt
} // namespace windows
} // namespace introvirt