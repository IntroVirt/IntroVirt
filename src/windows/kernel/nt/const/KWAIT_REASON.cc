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
#include <introvirt/windows/kernel/nt/const/KWAIT_REASON.hh>

namespace introvirt {
namespace windows {
namespace nt {

static const std::string ExecutiveStr("Executive");
static const std::string FreePageStr("FreePage");
static const std::string PageInStr("PageIn");
static const std::string PoolAllocationStr("PoolAllocation");
static const std::string DelayExecutionStr("DelayExecution");
static const std::string SuspendedStr("Suspended");
static const std::string UserRequestStr("UserRequest");
static const std::string WrExecutiveStr("WrExecutive");
static const std::string WrFreePageStr("WrFreePage");
static const std::string WrPageInStr("WrPageIn");
static const std::string WrPoolAllocationStr("WrPoolAllocation");
static const std::string WrDelayExecutionStr("WrDelayExecution");
static const std::string WrSuspendedStr("WrSuspended");
static const std::string WrUserRequestStr("WrUserRequest");
static const std::string WrSpare0Str("WrSpare0");
static const std::string WrQueueStr("WrQueue");
static const std::string WrLpcReceiveStr("WrLpcReceive");
static const std::string WrLpcReplyStr("WrLpcReply");
static const std::string WrVirtualMemoryStr("WrVirtualMemory");
static const std::string WrPageOutStr("WrPageOut");
static const std::string WrRendezvousStr("WrRendezvous");
static const std::string WrKeyedEventStr("WrKeyedEvent");
static const std::string WrTerminatedStr("WrTerminated");
static const std::string WrProcessInSwapStr("WrProcessInSwap");
static const std::string WrCpuRateControlStr("WrCpuRateControl");
static const std::string WrCalloutStackStr("WrCalloutStack");
static const std::string WrKernelStr("WrKernel");
static const std::string WrResourceStr("WrResource");
static const std::string WrPushLockStr("WrPushLock");
static const std::string WrMutexStr("WrMutex");
static const std::string WrQuantumEndStr("WrQuantumEnd");
static const std::string WrDispatchIntStr("WrDispatchInt");
static const std::string WrPreemptedStr("WrPreempted");
static const std::string WrYieldExecutionStr("WrYieldExecution");
static const std::string WrFastMutexStr("WrFastMutex");
static const std::string WrGuardedMutexStr("WrGuardedMutex");
static const std::string WrRundownStr("WrRundown");
static const std::string WrAlertByThreadIdStr("WrAlertByThreadId");
static const std::string WrDeferredPreemptStr("WrDeferredPreempt");
static const std::string WrPhysicalFaultStr("WrPhysicalFault");
static const std::string UnknownStr("Unknown");

const std::string& to_string(KWAIT_REASON reason) {
    switch (reason) {
    case KWAIT_REASON::Executive:
        return ExecutiveStr;
    case KWAIT_REASON::FreePage:
        return FreePageStr;
    case KWAIT_REASON::PageIn:
        return PageInStr;
    case KWAIT_REASON::PoolAllocation:
        return PoolAllocationStr;
    case KWAIT_REASON::DelayExecution:
        return DelayExecutionStr;
    case KWAIT_REASON::Suspended:
        return SuspendedStr;
    case KWAIT_REASON::UserRequest:
        return UserRequestStr;
    case KWAIT_REASON::WrExecutive:
        return WrExecutiveStr;
    case KWAIT_REASON::WrFreePage:
        return WrFreePageStr;
    case KWAIT_REASON::WrPageIn:
        return WrPageInStr;
    case KWAIT_REASON::WrPoolAllocation:
        return WrPoolAllocationStr;
    case KWAIT_REASON::WrDelayExecution:
        return WrDelayExecutionStr;
    case KWAIT_REASON::WrSuspended:
        return WrSuspendedStr;
    case KWAIT_REASON::WrUserRequest:
        return WrUserRequestStr;
    case KWAIT_REASON::WrSpare0:
        return WrSpare0Str;
    case KWAIT_REASON::WrQueue:
        return WrQueueStr;
    case KWAIT_REASON::WrLpcReceive:
        return WrLpcReceiveStr;
    case KWAIT_REASON::WrLpcReply:
        return WrLpcReplyStr;
    case KWAIT_REASON::WrVirtualMemory:
        return WrVirtualMemoryStr;
    case KWAIT_REASON::WrPageOut:
        return WrPageOutStr;
    case KWAIT_REASON::WrRendezvous:
        return WrRendezvousStr;
    case KWAIT_REASON::WrKeyedEvent:
        return WrKeyedEventStr;
    case KWAIT_REASON::WrTerminated:
        return WrTerminatedStr;
    case KWAIT_REASON::WrProcessInSwap:
        return WrProcessInSwapStr;
    case KWAIT_REASON::WrCpuRateControl:
        return WrCpuRateControlStr;
    case KWAIT_REASON::WrCalloutStack:
        return WrCalloutStackStr;
    case KWAIT_REASON::WrKernel:
        return WrKernelStr;
    case KWAIT_REASON::WrResource:
        return WrResourceStr;
    case KWAIT_REASON::WrPushLock:
        return WrPushLockStr;
    case KWAIT_REASON::WrMutex:
        return WrMutexStr;
    case KWAIT_REASON::WrQuantumEnd:
        return WrQuantumEndStr;
    case KWAIT_REASON::WrDispatchInt:
        return WrDispatchIntStr;
    case KWAIT_REASON::WrPreempted:
        return WrPreemptedStr;
    case KWAIT_REASON::WrYieldExecution:
        return WrYieldExecutionStr;
    case KWAIT_REASON::WrFastMutex:
        return WrFastMutexStr;
    case KWAIT_REASON::WrGuardedMutex:
        return WrGuardedMutexStr;
    case KWAIT_REASON::WrRundown:
        return WrRundownStr;
    case KWAIT_REASON::WrAlertByThreadId:
        return WrAlertByThreadIdStr;
    case KWAIT_REASON::WrDeferredPreempt:
        return WrDeferredPreemptStr;
    case KWAIT_REASON::WrPhysicalFault:
        return WrPhysicalFaultStr;
    case KWAIT_REASON::MaximumWaitReason:
        return UnknownStr;
    }
    return UnknownStr;
}

std::ostream& operator<<(std::ostream& os, KWAIT_REASON state) {
    os << to_string(state);
    return os;
}

} // namespace nt
} // namespace windows
} // namespace introvirt