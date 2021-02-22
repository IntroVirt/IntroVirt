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

#include <introvirt/windows/kernel/nt/syscall/types/thread_information/THREAD_INFORMATION_CLASS.hh>

namespace introvirt {
namespace windows {
namespace nt {

const std::string& to_string(THREAD_INFORMATION_CLASS infoClass) {
    static const std::string ThreadBasicInformationStr("ThreadBasicInformation");
    static const std::string ThreadTimesStr("ThreadTimes");
    static const std::string ThreadPriorityStr("ThreadPriority");
    static const std::string ThreadBasePriorityStr("ThreadBasePriority");
    static const std::string ThreadAffinityMaskStr("ThreadAffinityMask");
    static const std::string ThreadImpersonationTokenStr("ThreadImpersonationToken");
    static const std::string ThreadDescriptorTableEntryStr("ThreadDescriptorTableEntry");
    static const std::string ThreadEnableAlignmentFaultFixupStr("ThreadEnableAlignmentFaultFixup");
    static const std::string ThreadEventPair_ReusableStr("ThreadEventPair_Reusable");
    static const std::string ThreadQuerySetWin32StartAddressStr("ThreadQuerySetWin32StartAddress");
    static const std::string ThreadZeroTlsCellStr("ThreadZeroTlsCell");
    static const std::string ThreadPerformanceCountStr("ThreadPerformanceCount");
    static const std::string ThreadAmILastThreadStr("ThreadAmILastThread");
    static const std::string ThreadIdealProcessorStr("ThreadIdealProcessor");
    static const std::string ThreadPriorityBoostStr("ThreadPriorityBoost");
    static const std::string ThreadSetTlsArrayAddressStr("ThreadSetTlsArrayAddress");
    static const std::string ThreadIsIoPendingStr("ThreadIsIoPending");
    static const std::string ThreadHideFromDebuggerStr("ThreadHideFromDebugger");
    static const std::string ThreadBreakOnTerminationStr("ThreadBreakOnTermination");
    static const std::string ThreadSwitchLegacyStateStr("ThreadSwitchLegacyState");
    static const std::string ThreadIsTerminatedStr("ThreadIsTerminated");
    static const std::string ThreadLastSystemCallStr("ThreadLastSystemCall");
    static const std::string ThreadIoPriorityStr("ThreadIoPriority");
    static const std::string ThreadCycleTimeStr("ThreadCycleTime");
    static const std::string ThreadPagePriorityStr("ThreadPagePriority");
    static const std::string ThreadActualBasePriorityStr("ThreadActualBasePriority");
    static const std::string ThreadTebInformationStr("ThreadTebInformation");
    static const std::string ThreadCSwitchMonStr("ThreadCSwitchMon");
    static const std::string ThreadCSwitchPmuStr("ThreadCSwitchPmu");
    static const std::string ThreadWow64ContextStr("ThreadWow64Context");
    static const std::string ThreadGroupInformationStr("ThreadGroupInformation");
    static const std::string ThreadUmsInformationStr("ThreadUmsInformation");
    static const std::string ThreadCounterProfilingStr("ThreadCounterProfiling");
    static const std::string ThreadIdealProcessorExStr("ThreadIdealProcessorEx");
    static const std::string ThreadCpuAccountingInformationStr("ThreadCpuAccountingInformation");
    static const std::string ThreadSuspendCountStr("ThreadSuspendCount");
    static const std::string ThreadHeterogeneousCpuPolicyStr("ThreadHeterogeneousCpuPolicy");
    static const std::string ThreadContainerIdStr("ThreadContainerId");
    static const std::string ThreadNameInformationStr("ThreadNameInformation");
    static const std::string ThreadSelectedCpuSetsStr("ThreadSelectedCpuSets");
    static const std::string ThreadSystemThreadInformationStr("ThreadSystemThreadInformation");
    static const std::string ThreadActualGroupAffinityStr("ThreadActualGroupAffinity");
    static const std::string ThreadDynamicCodePolicyInfoStr("ThreadDynamicCodePolicyInfo");
    static const std::string ThreadExplicitCaseSensitivityStr("ThreadExplicitCaseSensitivity");
    static const std::string ThreadWorkOnBehalfTicketStr("ThreadWorkOnBehalfTicket");
    static const std::string ThreadSubsystemInformationStr("ThreadSubsystemInformation");
    static const std::string ThreadDbgkWerReportActiveStr("ThreadDbgkWerReportActive");
    static const std::string ThreadAttachContainerStr("ThreadAttachContainer");
    static const std::string ThreadManageWritesToExecutableMemoryStr(
        "ThreadManageWritesToExecutableMemory");
    static const std::string ThreadPowerThrottlingStateStr("ThreadPowerThrottlingState");
    static const std::string UnknownStr("Unknown");

    switch (infoClass) {
    case THREAD_INFORMATION_CLASS::ThreadBasicInformation:
        return ThreadBasicInformationStr;
    case THREAD_INFORMATION_CLASS::ThreadTimes:
        return ThreadTimesStr;
    case THREAD_INFORMATION_CLASS::ThreadPriority:
        return ThreadPriorityStr;
    case THREAD_INFORMATION_CLASS::ThreadBasePriority:
        return ThreadBasePriorityStr;
    case THREAD_INFORMATION_CLASS::ThreadAffinityMask:
        return ThreadAffinityMaskStr;
    case THREAD_INFORMATION_CLASS::ThreadImpersonationToken:
        return ThreadImpersonationTokenStr;
    case THREAD_INFORMATION_CLASS::ThreadDescriptorTableEntry:
        return ThreadDescriptorTableEntryStr;
    case THREAD_INFORMATION_CLASS::ThreadEnableAlignmentFaultFixup:
        return ThreadEnableAlignmentFaultFixupStr;
    case THREAD_INFORMATION_CLASS::ThreadEventPair_Reusable:
        return ThreadEventPair_ReusableStr;
    case THREAD_INFORMATION_CLASS::ThreadQuerySetWin32StartAddress:
        return ThreadQuerySetWin32StartAddressStr;
    case THREAD_INFORMATION_CLASS::ThreadZeroTlsCell:
        return ThreadZeroTlsCellStr;
    case THREAD_INFORMATION_CLASS::ThreadPerformanceCount:
        return ThreadPerformanceCountStr;
    case THREAD_INFORMATION_CLASS::ThreadAmILastThread:
        return ThreadAmILastThreadStr;
    case THREAD_INFORMATION_CLASS::ThreadIdealProcessor:
        return ThreadIdealProcessorStr;
    case THREAD_INFORMATION_CLASS::ThreadPriorityBoost:
        return ThreadPriorityBoostStr;
    case THREAD_INFORMATION_CLASS::ThreadSetTlsArrayAddress:
        return ThreadSetTlsArrayAddressStr;
    case THREAD_INFORMATION_CLASS::ThreadIsIoPending:
        return ThreadIsIoPendingStr;
    case THREAD_INFORMATION_CLASS::ThreadHideFromDebugger:
        return ThreadHideFromDebuggerStr;
    case THREAD_INFORMATION_CLASS::ThreadBreakOnTermination:
        return ThreadBreakOnTerminationStr;
    case THREAD_INFORMATION_CLASS::ThreadSwitchLegacyState:
        return ThreadSwitchLegacyStateStr;
    case THREAD_INFORMATION_CLASS::ThreadIsTerminated:
        return ThreadIsTerminatedStr;
    case THREAD_INFORMATION_CLASS::ThreadLastSystemCall:
        return ThreadLastSystemCallStr;
    case THREAD_INFORMATION_CLASS::ThreadIoPriority:
        return ThreadIoPriorityStr;
    case THREAD_INFORMATION_CLASS::ThreadCycleTime:
        return ThreadCycleTimeStr;
    case THREAD_INFORMATION_CLASS::ThreadPagePriority:
        return ThreadPagePriorityStr;
    case THREAD_INFORMATION_CLASS::ThreadActualBasePriority:
        return ThreadActualBasePriorityStr;
    case THREAD_INFORMATION_CLASS::ThreadTebInformation:
        return ThreadTebInformationStr;
    case THREAD_INFORMATION_CLASS::ThreadCSwitchMon:
        return ThreadCSwitchMonStr;
    case THREAD_INFORMATION_CLASS::ThreadCSwitchPmu:
        return ThreadCSwitchPmuStr;
    case THREAD_INFORMATION_CLASS::ThreadWow64Context:
        return ThreadWow64ContextStr;
    case THREAD_INFORMATION_CLASS::ThreadGroupInformation:
        return ThreadGroupInformationStr;
    case THREAD_INFORMATION_CLASS::ThreadUmsInformation:
        return ThreadUmsInformationStr;
    case THREAD_INFORMATION_CLASS::ThreadCounterProfiling:
        return ThreadCounterProfilingStr;
    case THREAD_INFORMATION_CLASS::ThreadIdealProcessorEx:
        return ThreadIdealProcessorExStr;
    case THREAD_INFORMATION_CLASS::ThreadCpuAccountingInformation:
        return ThreadCpuAccountingInformationStr;
    case THREAD_INFORMATION_CLASS::ThreadSuspendCount:
        return ThreadSuspendCountStr;
    case THREAD_INFORMATION_CLASS::ThreadHeterogeneousCpuPolicy:
        return ThreadHeterogeneousCpuPolicyStr;
    case THREAD_INFORMATION_CLASS::ThreadContainerId:
        return ThreadContainerIdStr;
    case THREAD_INFORMATION_CLASS::ThreadNameInformation:
        return ThreadNameInformationStr;
    case THREAD_INFORMATION_CLASS::ThreadSelectedCpuSets:
        return ThreadSelectedCpuSetsStr;
    case THREAD_INFORMATION_CLASS::ThreadSystemThreadInformation:
        return ThreadSystemThreadInformationStr;
    case THREAD_INFORMATION_CLASS::ThreadActualGroupAffinity:
        return ThreadActualGroupAffinityStr;
    case THREAD_INFORMATION_CLASS::ThreadDynamicCodePolicyInfo:
        return ThreadDynamicCodePolicyInfoStr;
    case THREAD_INFORMATION_CLASS::ThreadExplicitCaseSensitivity:
        return ThreadExplicitCaseSensitivityStr;
    case THREAD_INFORMATION_CLASS::ThreadWorkOnBehalfTicket:
        return ThreadWorkOnBehalfTicketStr;
    case THREAD_INFORMATION_CLASS::ThreadSubsystemInformation:
        return ThreadSubsystemInformationStr;
    case THREAD_INFORMATION_CLASS::ThreadDbgkWerReportActive:
        return ThreadDbgkWerReportActiveStr;
    case THREAD_INFORMATION_CLASS::ThreadAttachContainer:
        return ThreadAttachContainerStr;
    case THREAD_INFORMATION_CLASS::ThreadManageWritesToExecutableMemory:
        return ThreadManageWritesToExecutableMemoryStr;
    case THREAD_INFORMATION_CLASS::ThreadPowerThrottlingState:
        return ThreadPowerThrottlingStateStr;
    }

    return UnknownStr;
}

std::ostream& operator<<(std::ostream& os, THREAD_INFORMATION_CLASS infoClass) {
    os << to_string(infoClass);
    return os;
}

} /* namespace nt */
} /* namespace windows */
} /* namespace introvirt */
