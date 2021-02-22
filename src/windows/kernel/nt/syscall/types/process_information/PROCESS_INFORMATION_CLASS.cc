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

#include <introvirt/windows/kernel/nt/syscall/types/process_information/PROCESS_INFORMATION_CLASS.hh>

namespace introvirt {
namespace windows {
namespace nt {

const std::string& to_string(PROCESS_INFORMATION_CLASS infoClass) {
    static const std::string ProcessBasicInformationStr("ProcessBasicInformation");
    static const std::string ProcessQuotaLimitsStr("ProcessQuotaLimits");
    static const std::string ProcessIoCountersStr("ProcessIoCounters");
    static const std::string ProcessVmCountersStr("ProcessVmCounters");
    static const std::string ProcessTimesStr("ProcessTimes");
    static const std::string ProcessBasePriorityStr("ProcessBasePriority");
    static const std::string ProcessRaisePriorityStr("ProcessRaisePriority");
    static const std::string ProcessDebugPortStr("ProcessDebugPort");
    static const std::string ProcessExceptionPortStr("ProcessExceptionPort");
    static const std::string ProcessAccessTokenStr("ProcessAccessToken");
    static const std::string ProcessLdtInformationStr("ProcessLdtInformation");
    static const std::string ProcessLdtSizeStr("ProcessLdtSize");
    static const std::string ProcessDefaultHardErrorModeStr("ProcessDefaultHardErrorMode");
    static const std::string ProcessIoPortHandlersStr("ProcessIoPortHandlers");
    static const std::string ProcessPooledUsageAndLimitsStr("ProcessPooledUsageAndLimits");
    static const std::string ProcessWorkingSetWatchStr("ProcessWorkingSetWatch");
    static const std::string ProcessUserModeIOPLStr("ProcessUserModeIOPL");
    static const std::string ProcessEnableAlignmentFaultFixupStr(
        "ProcessEnableAlignmentFaultFixup");
    static const std::string ProcessPriorityClassStr("ProcessPriorityClass");
    static const std::string ProcessWx86InformationStr("ProcessWx86Information");
    static const std::string ProcessHandleCountStr("ProcessHandleCount");
    static const std::string ProcessAffinityMaskStr("ProcessAffinityMask");
    static const std::string ProcessPriorityBoostStr("ProcessPriorityBoost");
    static const std::string ProcessDeviceMapStr("ProcessDeviceMap");
    static const std::string ProcessSessionInformationStr("ProcessSessionInformation");
    static const std::string ProcessForegroundInformationStr("ProcessForegroundInformation");
    static const std::string ProcessWow64InformationStr("ProcessWow64Information");
    static const std::string ProcessImageFileNameStr("ProcessImageFileName");
    static const std::string ProcessLUIDDeviceMapsEnabledStr("ProcessLUIDDeviceMapsEnabled");
    static const std::string ProcessBreakOnTerminationStr("ProcessBreakOnTermination");
    static const std::string ProcessDebugObjectHandleStr("ProcessDebugObjectHandle");
    static const std::string ProcessDebugFlagsStr("ProcessDebugFlags");
    static const std::string ProcessHandleTracingStr("ProcessHandleTracing");
    static const std::string ProcessIoPriorityStr("ProcessIoPriority");
    static const std::string ProcessExecuteFlagsStr("ProcessExecuteFlags");
    static const std::string ProcessTlsInformationStr("ProcessTlsInformation");
    static const std::string ProcessCookieStr("ProcessCookie");
    static const std::string ProcessImageInformationStr("ProcessImageInformation");
    static const std::string ProcessCycleTimeStr("ProcessCycleTime");
    static const std::string ProcessPagePriorityStr("ProcessPagePriority");
    static const std::string ProcessInstrumentationCallbackStr("ProcessInstrumentationCallback");
    static const std::string ProcessThreadStackAllocationStr("ProcessThreadStackAllocation");
    static const std::string ProcessWorkingSetWatchExStr("ProcessWorkingSetWatchEx");
    static const std::string ProcessImageFileNameWin32Str("ProcessImageFileNameWin32");
    static const std::string ProcessImageFileMappingStr("ProcessImageFileMapping");
    static const std::string ProcessAffinityUpdateModeStr("ProcessAffinityUpdateMode");
    static const std::string ProcessMemoryAllocationModeStr("ProcessMemoryAllocationMode");
    static const std::string ProcessGroupInformationStr("ProcessGroupInformation");
    static const std::string ProcessTokenVirtualizationEnabledStr(
        "ProcessTokenVirtualizationEnabled");
    static const std::string ProcessConsoleHostProcessStr("ProcessConsoleHostProcess");
    static const std::string ProcessWindowInformationStr("ProcessWindowInformation");
    static const std::string ProcessHandleInformationStr("ProcessHandleInformation");
    static const std::string ProcessMitigationPolicyStr("ProcessMitigationPolicy");
    static const std::string ProcessDynamicFunctionTableInformationStr(
        "ProcessDynamicFunctionTableInformation");
    static const std::string ProcessHandleCheckingModeStr("ProcessHandleCheckingMode");
    static const std::string ProcessKeepAliveCountStr("ProcessKeepAliveCount");
    static const std::string ProcessRevokeFileHandlesStr("ProcessRevokeFileHandles");
    static const std::string ProcessWorkingSetControlStr("ProcessWorkingSetControl");
    static const std::string ProcessHandleTableStr("ProcessHandleTable");
    static const std::string ProcessCheckStackExtentsModeStr("ProcessCheckStackExtentsMode");
    static const std::string ProcessCommandLineInformationStr("ProcessCommandLineInformation");
    static const std::string ProcessProtectionInformationStr("ProcessProtectionInformation");
    static const std::string ProcessMemoryExhaustionStr("ProcessMemoryExhaustion");
    static const std::string ProcessFaultInformationStr("ProcessFaultInformation");
    static const std::string ProcessTelemetryIdInformationStr("ProcessTelemetryIdInformation");
    static const std::string ProcessCommitReleaseInformationStr("ProcessCommitReleaseInformation");
    static const std::string ProcessDefaultCpuSetsInformationStr(
        "ProcessDefaultCpuSetsInformation");
    static const std::string ProcessAllowedCpuSetsInformationStr(
        "ProcessAllowedCpuSetsInformation");
    static const std::string ProcessSubsystemProcessStr("ProcessSubsystemProcess");
    static const std::string ProcessJobMemoryInformationStr("ProcessJobMemoryInformation");
    static const std::string ProcessInPrivateStr("ProcessInPrivate");
    static const std::string ProcessRaiseUMExceptionOnInvalidHandleCloseStr(
        "ProcessRaiseUMExceptionOnInvalidHandleClose");
    static const std::string ProcessIumChallengeResponseStr("ProcessIumChallengeResponse");
    static const std::string ProcessChildProcessInformationStr("ProcessChildProcessInformation");
    static const std::string ProcessHighGraphicsPriorityInformationStr(
        "ProcessHighGraphicsPriorityInformation");
    static const std::string ProcessSubsystemInformationStr("ProcessSubsystemInformation");
    static const std::string ProcessEnergyValuesStr("ProcessEnergyValues");
    static const std::string ProcessActivityThrottleStateStr("ProcessActivityThrottleState");
    static const std::string ProcessActivityThrottlePolicyStr("ProcessActivityThrottlePolicy");
    static const std::string ProcessWin32kSyscallFilterInformationStr(
        "ProcessWin32kSyscallFilterInformation");
    static const std::string ProcessDisableSystemAllowedCpuSetsStr(
        "ProcessDisableSystemAllowedCpuSets");
    static const std::string ProcessWakeInformationStr("ProcessWakeInformation");
    static const std::string ProcessEnergyTrackingStateStr("ProcessEnergyTrackingState");
    static const std::string ProcessManageWritesToExecutableMemoryStr(
        "ProcessManageWritesToExecutableMemory");
    static const std::string ProcessCaptureTrustletLiveDumpStr("ProcessCaptureTrustletLiveDump");
    static const std::string ProcessTelemetryCoverageStr("ProcessTelemetryCoverage");
    static const std::string ProcessEnclaveInformationStr("ProcessEnclaveInformation");
    static const std::string ProcessEnableReadWriteVmLoggingStr("ProcessEnableReadWriteVmLogging");
    static const std::string ProcessUptimeInformationStr("ProcessUptimeInformation");
    static const std::string ProcessImageSectionStr("ProcessImageSection");
    static const std::string ProcessDebugAuthInformationStr("ProcessDebugAuthInformation");
    static const std::string ProcessSystemResourceManagementStr("ProcessSystemResourceManagement");
    static const std::string ProcessSequenceNumberStr("ProcessSequenceNumber");
    static const std::string ProcessLoaderDetourStr("ProcessLoaderDetour");
    static const std::string ProcessSecurityDomainInformationStr(
        "ProcessSecurityDomainInformation");
    static const std::string ProcessCombineSecurityDomainsInformationStr(
        "ProcessCombineSecurityDomainsInformation");
    static const std::string ProcessEnableLoggingStr("ProcessEnableLogging");
    static const std::string ProcessLeapSecondInformationStr("ProcessLeapSecondInformation");
    static const std::string ProcessFiberShadowStackAllocationStr(
        "ProcessFiberShadowStackAllocation");
    static const std::string ProcessFreeFiberShadowStackAllocationStr(
        "ProcessFreeFiberShadowStackAllocation");

    static const std::string UnknownStr("Unknown");

    switch (infoClass) {
    case PROCESS_INFORMATION_CLASS::ProcessBasicInformation:
        return ProcessBasicInformationStr;
    case PROCESS_INFORMATION_CLASS::ProcessQuotaLimits:
        return ProcessQuotaLimitsStr;
    case PROCESS_INFORMATION_CLASS::ProcessIoCounters:
        return ProcessIoCountersStr;
    case PROCESS_INFORMATION_CLASS::ProcessVmCounters:
        return ProcessVmCountersStr;
    case PROCESS_INFORMATION_CLASS::ProcessTimes:
        return ProcessTimesStr;
    case PROCESS_INFORMATION_CLASS::ProcessBasePriority:
        return ProcessBasePriorityStr;
    case PROCESS_INFORMATION_CLASS::ProcessRaisePriority:
        return ProcessRaisePriorityStr;
    case PROCESS_INFORMATION_CLASS::ProcessDebugPort:
        return ProcessDebugPortStr;
    case PROCESS_INFORMATION_CLASS::ProcessExceptionPort:
        return ProcessExceptionPortStr;
    case PROCESS_INFORMATION_CLASS::ProcessAccessToken:
        return ProcessAccessTokenStr;
    case PROCESS_INFORMATION_CLASS::ProcessLdtInformation:
        return ProcessLdtInformationStr;
    case PROCESS_INFORMATION_CLASS::ProcessLdtSize:
        return ProcessLdtSizeStr;
    case PROCESS_INFORMATION_CLASS::ProcessDefaultHardErrorMode:
        return ProcessDefaultHardErrorModeStr;
    case PROCESS_INFORMATION_CLASS::ProcessIoPortHandlers:
        return ProcessIoPortHandlersStr;
    case PROCESS_INFORMATION_CLASS::ProcessPooledUsageAndLimits:
        return ProcessPooledUsageAndLimitsStr;
    case PROCESS_INFORMATION_CLASS::ProcessWorkingSetWatch:
        return ProcessWorkingSetWatchStr;
    case PROCESS_INFORMATION_CLASS::ProcessUserModeIOPL:
        return ProcessUserModeIOPLStr;
    case PROCESS_INFORMATION_CLASS::ProcessEnableAlignmentFaultFixup:
        return ProcessEnableAlignmentFaultFixupStr;
    case PROCESS_INFORMATION_CLASS::ProcessPriorityClass:
        return ProcessPriorityClassStr;
    case PROCESS_INFORMATION_CLASS::ProcessWx86Information:
        return ProcessWx86InformationStr;
    case PROCESS_INFORMATION_CLASS::ProcessHandleCount:
        return ProcessHandleCountStr;
    case PROCESS_INFORMATION_CLASS::ProcessAffinityMask:
        return ProcessAffinityMaskStr;
    case PROCESS_INFORMATION_CLASS::ProcessPriorityBoost:
        return ProcessPriorityBoostStr;
    case PROCESS_INFORMATION_CLASS::ProcessDeviceMap:
        return ProcessDeviceMapStr;
    case PROCESS_INFORMATION_CLASS::ProcessSessionInformation:
        return ProcessSessionInformationStr;
    case PROCESS_INFORMATION_CLASS::ProcessForegroundInformation:
        return ProcessForegroundInformationStr;
    case PROCESS_INFORMATION_CLASS::ProcessWow64Information:
        return ProcessWow64InformationStr;
    case PROCESS_INFORMATION_CLASS::ProcessImageFileName:
        return ProcessImageFileNameStr;
    case PROCESS_INFORMATION_CLASS::ProcessLUIDDeviceMapsEnabled:
        return ProcessLUIDDeviceMapsEnabledStr;
    case PROCESS_INFORMATION_CLASS::ProcessBreakOnTermination:
        return ProcessBreakOnTerminationStr;
    case PROCESS_INFORMATION_CLASS::ProcessDebugObjectHandle:
        return ProcessDebugObjectHandleStr;
    case PROCESS_INFORMATION_CLASS::ProcessDebugFlags:
        return ProcessDebugFlagsStr;
    case PROCESS_INFORMATION_CLASS::ProcessHandleTracing:
        return ProcessHandleTracingStr;
    case PROCESS_INFORMATION_CLASS::ProcessIoPriority:
        return ProcessIoPriorityStr;
    case PROCESS_INFORMATION_CLASS::ProcessExecuteFlags:
        return ProcessExecuteFlagsStr;
    case PROCESS_INFORMATION_CLASS::ProcessTlsInformation:
        return ProcessTlsInformationStr;
    case PROCESS_INFORMATION_CLASS::ProcessCookie:
        return ProcessCookieStr;
    case PROCESS_INFORMATION_CLASS::ProcessImageInformation:
        return ProcessImageInformationStr;
    case PROCESS_INFORMATION_CLASS::ProcessCycleTime:
        return ProcessCycleTimeStr;
    case PROCESS_INFORMATION_CLASS::ProcessPagePriority:
        return ProcessPagePriorityStr;
    case PROCESS_INFORMATION_CLASS::ProcessInstrumentationCallback:
        return ProcessInstrumentationCallbackStr;
    case PROCESS_INFORMATION_CLASS::ProcessThreadStackAllocation:
        return ProcessThreadStackAllocationStr;
    case PROCESS_INFORMATION_CLASS::ProcessWorkingSetWatchEx:
        return ProcessWorkingSetWatchExStr;
    case PROCESS_INFORMATION_CLASS::ProcessImageFileNameWin32:
        return ProcessImageFileNameWin32Str;
    case PROCESS_INFORMATION_CLASS::ProcessImageFileMapping:
        return ProcessImageFileMappingStr;
    case PROCESS_INFORMATION_CLASS::ProcessAffinityUpdateMode:
        return ProcessAffinityUpdateModeStr;
    case PROCESS_INFORMATION_CLASS::ProcessMemoryAllocationMode:
        return ProcessMemoryAllocationModeStr;
    case PROCESS_INFORMATION_CLASS::ProcessGroupInformation:
        return ProcessGroupInformationStr;
    case PROCESS_INFORMATION_CLASS::ProcessTokenVirtualizationEnabled:
        return ProcessTokenVirtualizationEnabledStr;
    case PROCESS_INFORMATION_CLASS::ProcessConsoleHostProcess:
        return ProcessConsoleHostProcessStr;
    case PROCESS_INFORMATION_CLASS::ProcessWindowInformation:
        return ProcessWindowInformationStr;
    case PROCESS_INFORMATION_CLASS::ProcessHandleInformation:
        return ProcessHandleInformationStr;
    case PROCESS_INFORMATION_CLASS::ProcessMitigationPolicy:
        return ProcessMitigationPolicyStr;
    case PROCESS_INFORMATION_CLASS::ProcessDynamicFunctionTableInformation:
        return ProcessDynamicFunctionTableInformationStr;
    case PROCESS_INFORMATION_CLASS::ProcessHandleCheckingMode:
        return ProcessHandleCheckingModeStr;
    case PROCESS_INFORMATION_CLASS::ProcessKeepAliveCount:
        return ProcessKeepAliveCountStr;
    case PROCESS_INFORMATION_CLASS::ProcessRevokeFileHandles:
        return ProcessRevokeFileHandlesStr;
    case PROCESS_INFORMATION_CLASS::ProcessWorkingSetControl:
        return ProcessWorkingSetControlStr;
    case PROCESS_INFORMATION_CLASS::ProcessHandleTable:
        return ProcessHandleTableStr;
    case PROCESS_INFORMATION_CLASS::ProcessCheckStackExtentsMode:
        return ProcessCheckStackExtentsModeStr;
    case PROCESS_INFORMATION_CLASS::ProcessCommandLineInformation:
        return ProcessCommandLineInformationStr;
    case PROCESS_INFORMATION_CLASS::ProcessProtectionInformation:
        return ProcessProtectionInformationStr;
    case PROCESS_INFORMATION_CLASS::ProcessMemoryExhaustion:
        return ProcessMemoryExhaustionStr;
    case PROCESS_INFORMATION_CLASS::ProcessFaultInformation:
        return ProcessFaultInformationStr;
    case PROCESS_INFORMATION_CLASS::ProcessTelemetryIdInformation:
        return ProcessTelemetryIdInformationStr;
    case PROCESS_INFORMATION_CLASS::ProcessCommitReleaseInformation:
        return ProcessCommitReleaseInformationStr;
    case PROCESS_INFORMATION_CLASS::ProcessDefaultCpuSetsInformation:
        return ProcessDefaultCpuSetsInformationStr;
    case PROCESS_INFORMATION_CLASS::ProcessAllowedCpuSetsInformation:
        return ProcessAllowedCpuSetsInformationStr;
    case PROCESS_INFORMATION_CLASS::ProcessSubsystemProcess:
        return ProcessSubsystemProcessStr;
    case PROCESS_INFORMATION_CLASS::ProcessJobMemoryInformation:
        return ProcessJobMemoryInformationStr;
    case PROCESS_INFORMATION_CLASS::ProcessInPrivate:
        return ProcessInPrivateStr;
    case PROCESS_INFORMATION_CLASS::ProcessRaiseUMExceptionOnInvalidHandleClose:
        return ProcessRaiseUMExceptionOnInvalidHandleCloseStr;
    case PROCESS_INFORMATION_CLASS::ProcessIumChallengeResponse:
        return ProcessIumChallengeResponseStr;
    case PROCESS_INFORMATION_CLASS::ProcessChildProcessInformation:
        return ProcessChildProcessInformationStr;
    case PROCESS_INFORMATION_CLASS::ProcessHighGraphicsPriorityInformation:
        return ProcessHighGraphicsPriorityInformationStr;
    case PROCESS_INFORMATION_CLASS::ProcessSubsystemInformation:
        return ProcessSubsystemInformationStr;
    case PROCESS_INFORMATION_CLASS::ProcessEnergyValues:
        return ProcessEnergyValuesStr;
    case PROCESS_INFORMATION_CLASS::ProcessActivityThrottleState:
        return ProcessActivityThrottleStateStr;
    case PROCESS_INFORMATION_CLASS::ProcessActivityThrottlePolicy:
        return ProcessActivityThrottlePolicyStr;
    case PROCESS_INFORMATION_CLASS::ProcessWin32kSyscallFilterInformation:
        return ProcessWin32kSyscallFilterInformationStr;
    case PROCESS_INFORMATION_CLASS::ProcessDisableSystemAllowedCpuSets:
        return ProcessDisableSystemAllowedCpuSetsStr;
    case PROCESS_INFORMATION_CLASS::ProcessWakeInformation:
        return ProcessWakeInformationStr;
    case PROCESS_INFORMATION_CLASS::ProcessEnergyTrackingState:
        return ProcessEnergyTrackingStateStr;
    case PROCESS_INFORMATION_CLASS::ProcessManageWritesToExecutableMemory:
        return ProcessManageWritesToExecutableMemoryStr;
    case PROCESS_INFORMATION_CLASS::ProcessCaptureTrustletLiveDump:
        return ProcessCaptureTrustletLiveDumpStr;
    case PROCESS_INFORMATION_CLASS::ProcessTelemetryCoverage:
        return ProcessTelemetryCoverageStr;
    case PROCESS_INFORMATION_CLASS::ProcessEnclaveInformation:
        return ProcessEnclaveInformationStr;
    case PROCESS_INFORMATION_CLASS::ProcessEnableReadWriteVmLogging:
        return ProcessEnableReadWriteVmLoggingStr;
    case PROCESS_INFORMATION_CLASS::ProcessUptimeInformation:
        return ProcessUptimeInformationStr;
    case PROCESS_INFORMATION_CLASS::ProcessImageSection:
        return ProcessImageSectionStr;
    case PROCESS_INFORMATION_CLASS::ProcessDebugAuthInformation:
        return ProcessDebugAuthInformationStr;
    case PROCESS_INFORMATION_CLASS::ProcessSystemResourceManagement:
        return ProcessSystemResourceManagementStr;
    case PROCESS_INFORMATION_CLASS::ProcessSequenceNumber:
        return ProcessSequenceNumberStr;
    case PROCESS_INFORMATION_CLASS::ProcessLoaderDetour:
        return ProcessLoaderDetourStr;
    case PROCESS_INFORMATION_CLASS::ProcessSecurityDomainInformation:
        return ProcessSecurityDomainInformationStr;
    case PROCESS_INFORMATION_CLASS::ProcessCombineSecurityDomainsInformation:
        return ProcessCombineSecurityDomainsInformationStr;
    case PROCESS_INFORMATION_CLASS::ProcessEnableLogging:
        return ProcessEnableLoggingStr;
    case PROCESS_INFORMATION_CLASS::ProcessLeapSecondInformation:
        return ProcessLeapSecondInformationStr;
    case PROCESS_INFORMATION_CLASS::ProcessFiberShadowStackAllocation:
        return ProcessFiberShadowStackAllocationStr;
    case PROCESS_INFORMATION_CLASS::ProcessFreeFiberShadowStackAllocation:
        return ProcessFreeFiberShadowStackAllocationStr;
    };

    return UnknownStr;
}

std::ostream& operator<<(std::ostream& os, PROCESS_INFORMATION_CLASS info_class) {
    os << to_string(info_class);
    return os;
}

} /* namespace nt */
} /* namespace windows */
} /* namespace introvirt */
