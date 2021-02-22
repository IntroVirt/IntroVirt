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
#include "THREAD_IMPL.hh"
#include "windows/kernel/nt/NtKernelImpl.hh"

#include <introvirt/windows/WindowsGuest.hh>
#include <introvirt/windows/event/WindowsEvent.hh>
#include <introvirt/windows/exception/InvalidStructureException.hh>
#include <introvirt/windows/kernel/nt/NtKernel.hh>
#include <introvirt/windows/kernel/nt/const/KTHREAD_STATE.hh>
#include <introvirt/windows/kernel/nt/const/ObjectType.hh>
#include <introvirt/windows/kernel/nt/types/objects/PROCESS.hh>

#include <log4cxx/logger.h>

namespace introvirt {
namespace windows {
namespace nt {

static log4cxx::LoggerPtr
    logger(log4cxx::Logger::getLogger("introvirt.windows.kernel.nt.types.THREAD"));

template <typename PtrType>
const CLIENT_ID& THREAD_IMPL<PtrType>::Cid() const {
    return Cid_;
}

template <typename PtrType>
const PROCESS& THREAD_IMPL<PtrType>::Process() const {
    std::lock_guard lock(mtx_);
    if (unlikely(!Process_)) {
        if (unlikely(Cid().UniqueProcess() == 0))
            throw InvalidStructureException("Idle THREAD does not have a PROCESS object");

        throw InvalidStructureException("THREAD has NULL process");
    }

    return *Process_;
}

template <typename PtrType>
PROCESS& THREAD_IMPL<PtrType>::Process() {
    const auto* const_this = this;
    return const_cast<PROCESS&>(const_this->Process());
}

template <typename PtrType>
int8_t THREAD_IMPL<PtrType>::BasePriority() const {
    return offsets_->Tcb.BasePriority.get<int8_t>(buffer_.get());
}

template <typename PtrType>
void THREAD_IMPL<PtrType>::BasePriority(int8_t priority) {
    offsets_->Tcb.BasePriority.set<int8_t>(buffer_.get(), priority);
}

template <typename PtrType>
int8_t THREAD_IMPL<PtrType>::Priority() const {
    return offsets_->Tcb.Priority.get<int8_t>(buffer_.get());
}

template <typename PtrType>
void THREAD_IMPL<PtrType>::Priority(int8_t priority) {
    offsets_->Tcb.Priority.set<int8_t>(buffer_.get(), priority);
}

template <typename PtrType>
GuestVirtualAddress THREAD_IMPL<PtrType>::Win32StartAddress() const {
    // TODO: The resulting VCPU should probably be based on the process' address space
    return this->address().create(offsets_->Win32StartAddress.get<PtrType>(buffer_.get()));
}

template <typename PtrType>
uint32_t THREAD_IMPL<PtrType>::CrossThreadFlags() const {
    return offsets_->CrossThreadFlags.get<uint32_t>(buffer_.get());
}

template <typename PtrType>
void THREAD_IMPL<PtrType>::CrossThreadFlags(uint32_t CrossThreadFlags) {
    offsets_->CrossThreadFlags.set<uint32_t>(buffer_.get(), CrossThreadFlags);
}

template <typename PtrType>
KTHREAD_STATE THREAD_IMPL<PtrType>::State() const {
    auto state = static_cast<KTHREAD_STATE>(offsets_->Tcb.State.get<uint8_t>(buffer_.get()));
    switch (state) {
    case KTHREAD_STATE::Initialized:
    case KTHREAD_STATE::Ready:
    case KTHREAD_STATE::Running:
    case KTHREAD_STATE::Standby:
    case KTHREAD_STATE::Terminated:
    case KTHREAD_STATE::Waiting:
    case KTHREAD_STATE::Transition:
    case KTHREAD_STATE::DeferredReady:
    case KTHREAD_STATE::GateWait:
    case KTHREAD_STATE::UnknownThreadState:
        return state;
    }
    return KTHREAD_STATE::UnknownThreadState;
}

template <typename PtrType>
void THREAD_IMPL<PtrType>::State(KTHREAD_STATE state) {
    offsets_->Tcb.State.set<uint8_t>(buffer_.get(), static_cast<uint8_t>(state));
}

template <typename PtrType>
bool THREAD_IMPL<PtrType>::Preempted() const {
    return offsets_->Tcb.Preempted.get<bool>(buffer_.get());
}

template <typename PtrType>
void THREAD_IMPL<PtrType>::Preempted(bool Preempted) {
    offsets_->Tcb.Preempted.set<bool>(buffer_.get(), Preempted);
}

template <typename PtrType>
int8_t THREAD_IMPL<PtrType>::Saturation() const {
    return offsets_->Tcb.Saturation.get<int8_t>(buffer_.get());
}

template <typename PtrType>
void THREAD_IMPL<PtrType>::Saturation(int8_t saturation) {
    offsets_->Tcb.Saturation.set<int8_t>(buffer_.get(), saturation);
}

template <typename PtrType>
const TEB* THREAD_IMPL<PtrType>::Teb() const {
    // TODO: The TEB pointer should be based on the process' address space
    std::lock_guard lock(mtx_);
    if (!Teb_) {
        // TODO: If the thread doesn't have a process we need to deal with that somehow
        const GuestVirtualAddress pTeb(
            this->gva_.create(offsets_->Tcb.Teb.get<PtrType>(buffer_.get())));

        if (pTeb)
            Teb_.emplace(kernel_, pTeb);
        else
            return nullptr;
    }
    return &(*Teb_);
}

template <typename PtrType>
TEB* THREAD_IMPL<PtrType>::Teb() {
    const auto* const_this = this;
    return const_cast<TEB*>(const_this->Teb());
}

template <typename PtrType>
uint64_t THREAD_IMPL<PtrType>::Affinity() const {
    return offsets_->Tcb.Affinity.get<PtrType>(buffer_.get());
}

template <typename PtrType>
void THREAD_IMPL<PtrType>::Affinity(uint64_t affinity) {
    offsets_->Tcb.Affinity.set<PtrType>(buffer_.get(), affinity);
}

template <typename PtrType>
uint64_t THREAD_IMPL<PtrType>::UserAffinity() const {
    return offsets_->Tcb.UserAffinity.get<PtrType>(buffer_.get());
}

template <typename PtrType>
void THREAD_IMPL<PtrType>::UserAffinity(uint64_t affinity) {
    offsets_->Tcb.UserAffinity.set<PtrType>(buffer_.get(), affinity);
}

template <typename PtrType>
uint32_t THREAD_IMPL<PtrType>::IdealProcessor() const {
    return offsets_->Tcb.IdealProcessor.get<uint32_t>(buffer_.get());
}

template <typename PtrType>
void THREAD_IMPL<PtrType>::IdealProcessor(uint32_t processor) {
    offsets_->Tcb.IdealProcessor.set<uint32_t>(buffer_.get(), processor);
}

template <typename PtrType>
uint32_t THREAD_IMPL<PtrType>::UserIdealProcessor() const {
    return offsets_->Tcb.UserIdealProcessor.get<uint32_t>(buffer_.get());
}

template <typename PtrType>
void THREAD_IMPL<PtrType>::UserIdealProcessor(uint32_t processor) {
    offsets_->Tcb.UserIdealProcessor.set<uint32_t>(buffer_.get(), processor);
}

template <typename PtrType>
int16_t THREAD_IMPL<PtrType>::KernelApcDisable() const {
    return offsets_->Tcb.KernelApcDisable.get<int16_t>(buffer_.get());
}

template <typename PtrType>
void THREAD_IMPL<PtrType>::KernelApcDisable(int16_t val) {
    offsets_->Tcb.KernelApcDisable.set<int16_t>(buffer_.get(), val);
}

template <typename PtrType>
int16_t THREAD_IMPL<PtrType>::SpecialApcDisable() const {
    if (offsets_->Tcb.SpecialApcDisable.exists())
        return offsets_->Tcb.SpecialApcDisable.get<int16_t>(buffer_.get());
    return 0;
}

template <typename PtrType>
void THREAD_IMPL<PtrType>::SpecialApcDisable(int16_t val) {
    if (offsets_->Tcb.SpecialApcDisable.exists())
        offsets_->Tcb.SpecialApcDisable.set<int16_t>(buffer_.get(), val);
}

template <typename PtrType>
uint8_t THREAD_IMPL<PtrType>::PreviousMode() const {
    return offsets_->Tcb.PreviousMode.get<uint8_t>(buffer_.get());
}

template <typename PtrType>
void THREAD_IMPL<PtrType>::PreviousMode(uint8_t mode) {
    offsets_->Tcb.PreviousMode.set<uint8_t>(buffer_.get(), mode);
}

template <typename PtrType>
uint64_t THREAD_IMPL<PtrType>::InitialStack() const {
    return offsets_->Tcb.InitialStack.get<PtrType>(buffer_.get());
}

template <typename PtrType>
uint64_t THREAD_IMPL<PtrType>::StackBase() const {
    return offsets_->Tcb.StackBase.get<PtrType>(buffer_.get());
}

template <typename PtrType>
uint64_t THREAD_IMPL<PtrType>::StackLimit() const {
    return offsets_->Tcb.StackLimit.get<PtrType>(buffer_.get());
}

template <typename PtrType>
uint64_t THREAD_IMPL<PtrType>::KernelStack() const {
    return offsets_->Tcb.KernelStack.get<PtrType>(buffer_.get());
}

template <typename PtrType>
WindowsTime THREAD_IMPL<PtrType>::CreateTime() const {
    return WindowsTime::from_windows_time(offsets_->CreateTime.get<int64_t>(buffer_.get()));
}

template <typename PtrType>
void THREAD_IMPL<PtrType>::CreateTime(const WindowsTime& time) {
    offsets_->CreateTime.set<int64_t>(buffer_.get(), time.windows_time());
}

template <typename PtrType>
bool THREAD_IMPL<PtrType>::DisableDynamicCodeOptOut() const {
    return CrossThreadFlags() & CT_DISABLE_DYNAMIC_CODE_OPT_OUT;
}

template <typename PtrType>
void THREAD_IMPL<PtrType>::DisableDynamicCodeOptOut(bool DisableDynamicCodeOptOut) {
    uint32_t new_value;
    if (DisableDynamicCodeOptOut) {
        new_value = CrossThreadFlags() | CT_DISABLE_DYNAMIC_CODE_OPT_OUT;
    } else {
        new_value = CrossThreadFlags() & ~(CT_DISABLE_DYNAMIC_CODE_OPT_OUT);
    }
    CrossThreadFlags(new_value);
}

template <typename PtrType>
THREAD_IMPL<PtrType>::THREAD_IMPL(const NtKernelImpl<PtrType>& kernel,
                                  const GuestVirtualAddress& gva)
    : DISPATCHER_OBJECT_IMPL<PtrType, THREAD>(kernel, gva, ObjectType::Thread), kernel_(kernel),
      offsets_(LoadOffsets<structs::ETHREAD>(kernel)), Cid_(gva + offsets_->Cid.offset()) {

    buffer_.reset(gva, offsets_->size());

    // Load up the PROCESS instance
    const auto pProcess =
        this->gva_.create(offsets_->Tcb.ApcState.Process.get<PtrType>(buffer_.get()));

    // Get the process from the kernel cache
    Process_ = kernel_.process(pProcess);

    // Use the DTB from the process
    if (Process_) {
        this->gva_.page_directory(Process_->DirectoryTableBase());
    }
}

template <typename PtrType>
THREAD_IMPL<PtrType>::THREAD_IMPL(const NtKernelImpl<PtrType>& kernel,
                                  std::unique_ptr<OBJECT_HEADER_IMPL<PtrType>>&& object_header)
    : DISPATCHER_OBJECT_IMPL<PtrType, THREAD>(kernel, std::move(object_header), ObjectType::Thread),
      kernel_(kernel), offsets_(LoadOffsets<structs::ETHREAD>(kernel)),
      Cid_(OBJECT_IMPL<PtrType, THREAD>::address() + offsets_->Cid.offset()) {

    buffer_.reset(OBJECT_IMPL<PtrType, THREAD>::address(), offsets_->size());

    // Load up the PROCESS instance
    const auto pProcess = OBJECT_IMPL<PtrType, THREAD>::address().create(
        offsets_->Tcb.ApcState.Process.get<PtrType>(buffer_.get()));

    // Get the process from the kernel cache
    Process_ = kernel_.process(pProcess);

    // Use the DTB from the process
    if (Process_) {
        this->gva_.page_directory(Process_->DirectoryTableBase());
    }
}

std::shared_ptr<THREAD> THREAD::make_shared(const NtKernel& kernel,
                                            const GuestVirtualAddress& gva) {
    if (kernel.x64())
        return std::make_shared<THREAD_IMPL<uint64_t>>(
            static_cast<const NtKernelImpl<uint64_t>&>(kernel), gva);
    else
        return std::make_shared<THREAD_IMPL<uint32_t>>(
            static_cast<const NtKernelImpl<uint32_t>&>(kernel), gva);
}

std::shared_ptr<THREAD> THREAD::make_shared(const NtKernel& kernel,
                                            std::unique_ptr<OBJECT_HEADER>&& object_header) {
    if (kernel.x64()) {
        std::unique_ptr<OBJECT_HEADER_IMPL<uint64_t>> object_header_impl;
        object_header_impl.reset(
            static_cast<OBJECT_HEADER_IMPL<uint64_t>*>(object_header.release()));
        return std::make_shared<THREAD_IMPL<uint64_t>>(
            static_cast<const NtKernelImpl<uint64_t>&>(kernel), std::move(object_header_impl));
    } else {
        std::unique_ptr<OBJECT_HEADER_IMPL<uint32_t>> object_header_impl;
        object_header_impl.reset(
            static_cast<OBJECT_HEADER_IMPL<uint32_t>*>(object_header.release()));
        return std::make_shared<THREAD_IMPL<uint32_t>>(
            static_cast<const NtKernelImpl<uint32_t>&>(kernel), std::move(object_header_impl));
    }
}

//
// Cross Thread Flags
//
bool THREAD::CrossThreadFlags::CT_TERMINATED_BIT() const {
    return value_ & CT_FLAGS::CT_TERMINATED_BIT;
}
bool THREAD::CrossThreadFlags::CT_DEAD_THREAD_BIT() const {
    return value_ & CT_FLAGS::CT_DEAD_THREAD_BIT;
}
bool THREAD::CrossThreadFlags::CT_HIDE_FROM_DEBUGGER_BIT() const {
    return value_ & CT_FLAGS::CT_HIDE_FROM_DEBUGGER_BIT;
}
bool THREAD::CrossThreadFlags::CT_ACTIVE_IMPERSONATION_INFO_BIT() const {
    return value_ & CT_FLAGS::CT_ACTIVE_IMPERSONATION_INFO_BIT;
}
bool THREAD::CrossThreadFlags::CT_SYSTEM_THREAD_BIT() const {
    return value_ & CT_FLAGS::CT_SYSTEM_THREAD_BIT;
}
bool THREAD::CrossThreadFlags::CT_HARD_ERRORS_ARE_DISABLED_BIT() const {
    return value_ & CT_FLAGS::CT_HARD_ERRORS_ARE_DISABLED_BIT;
}
bool THREAD::CrossThreadFlags::CT_BREAK_ON_TERMINATION_BIT() const {
    return value_ & CT_FLAGS::CT_BREAK_ON_TERMINATION_BIT;
}
bool THREAD::CrossThreadFlags::CT_SKIP_CREATION_MSG_BIT() const {
    return value_ & CT_FLAGS::CT_SKIP_CREATION_MSG_BIT;
}
bool THREAD::CrossThreadFlags::CT_SKIP_TERMINATION_MSG_BIT() const {
    return value_ & CT_FLAGS::CT_SKIP_TERMINATION_MSG_BIT;
}
bool THREAD::CrossThreadFlags::CT_INDIRECT_CPU_SETS() const {
    return value_ & CT_FLAGS::CT_INDIRECT_CPU_SETS;
}
bool THREAD::CrossThreadFlags::CT_DISABLE_DYNAMIC_CODE_OPT_OUT() const {
    return value_ & CT_FLAGS::CT_DISABLE_DYNAMIC_CODE_OPT_OUT;
}

template class THREAD_IMPL<uint32_t>;
template class THREAD_IMPL<uint64_t>;

} // namespace nt
} // namespace windows
} // namespace introvirt