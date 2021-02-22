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

#include <introvirt/windows/kernel/nt/syscall/types/system_information/SYSTEM_INFORMATION_CLASS.hh>

namespace introvirt {
namespace windows {
namespace nt {

/**
 * See http://www.exploit-monday.com/2013/06/undocumented-ntquerysysteminformation.html
 */

bool valid(SYSTEM_INFORMATION_CLASS information_class) {
    switch (information_class) {
    case SYSTEM_INFORMATION_CLASS::SystemBasicInformation:
    case SYSTEM_INFORMATION_CLASS::SystemProcessorInformation:
    case SYSTEM_INFORMATION_CLASS::SystemPerformanceInformation:
    case SYSTEM_INFORMATION_CLASS::SystemTimeOfDayInformation:
    case SYSTEM_INFORMATION_CLASS::SystemPathInformation:
    case SYSTEM_INFORMATION_CLASS::SystemProcessInformation:
    case SYSTEM_INFORMATION_CLASS::SystemCallCountInformation:
    case SYSTEM_INFORMATION_CLASS::SystemDeviceInformation:
    case SYSTEM_INFORMATION_CLASS::SystemProcessorPerformanceInformation:
    case SYSTEM_INFORMATION_CLASS::SystemFlagsInformation:
    case SYSTEM_INFORMATION_CLASS::SystemCallTimeInformation:
    case SYSTEM_INFORMATION_CLASS::SystemModuleInformation:
    case SYSTEM_INFORMATION_CLASS::SystemLocksInformation:
    case SYSTEM_INFORMATION_CLASS::SystemStackTraceInformation:
    case SYSTEM_INFORMATION_CLASS::SystemPagedPoolInformation:
    case SYSTEM_INFORMATION_CLASS::SystemNonPagedPoolInformation:
    case SYSTEM_INFORMATION_CLASS::SystemHandleInformation:
    case SYSTEM_INFORMATION_CLASS::SystemObjectInformation:
    case SYSTEM_INFORMATION_CLASS::SystemPageFileInformation:
    case SYSTEM_INFORMATION_CLASS::SystemVdmInstemulInformation:
    case SYSTEM_INFORMATION_CLASS::SystemVdmBopInformation:
    case SYSTEM_INFORMATION_CLASS::SystemFileCacheInformation:
    case SYSTEM_INFORMATION_CLASS::SystemPoolTagInformation:
    case SYSTEM_INFORMATION_CLASS::SystemInterruptInformation:
    case SYSTEM_INFORMATION_CLASS::SystemDpcBehaviorInformation:
    case SYSTEM_INFORMATION_CLASS::SystemFullMemoryInformation:
    case SYSTEM_INFORMATION_CLASS::SystemLoadGdiDriverInformation:
    case SYSTEM_INFORMATION_CLASS::SystemUnloadGdiDriverInformation:
    case SYSTEM_INFORMATION_CLASS::SystemTimeAdjustmentInformation:
    case SYSTEM_INFORMATION_CLASS::SystemSummaryMemoryInformation:
    case SYSTEM_INFORMATION_CLASS::SystemMirrorMemoryInformation:
    case SYSTEM_INFORMATION_CLASS::SystemPerformanceTraceInformation:
    case SYSTEM_INFORMATION_CLASS::SystemCrashDumpInformation:
    case SYSTEM_INFORMATION_CLASS::SystemExceptionInformation:
    case SYSTEM_INFORMATION_CLASS::SystemCrashDumpStateInformation:
    case SYSTEM_INFORMATION_CLASS::SystemKernelDebuggerInformation:
    case SYSTEM_INFORMATION_CLASS::SystemContextSwitchInformation:
    case SYSTEM_INFORMATION_CLASS::SystemRegistryQuotaInformation:
    case SYSTEM_INFORMATION_CLASS::SystemExtendServiceTableInformation:
    case SYSTEM_INFORMATION_CLASS::SystemPrioritySeperation:
    case SYSTEM_INFORMATION_CLASS::SystemVerifierAddDriverInformation:
    case SYSTEM_INFORMATION_CLASS::SystemVerifierRemoveDriverInformation:
    case SYSTEM_INFORMATION_CLASS::SystemProcessorIdleInformation:
    case SYSTEM_INFORMATION_CLASS::SystemLegacyDriverInformation:
    case SYSTEM_INFORMATION_CLASS::SystemCurrentTimeZoneInformation:
    case SYSTEM_INFORMATION_CLASS::SystemLookasideInformation:
    case SYSTEM_INFORMATION_CLASS::SystemTimeSlipNotification:
    case SYSTEM_INFORMATION_CLASS::SystemSessionCreate:
    case SYSTEM_INFORMATION_CLASS::SystemSessionDetach:
    case SYSTEM_INFORMATION_CLASS::SystemSessionInformation:
    case SYSTEM_INFORMATION_CLASS::SystemRangeStartInformation:
    case SYSTEM_INFORMATION_CLASS::SystemVerifierInformation:
    case SYSTEM_INFORMATION_CLASS::SystemVerifierThunkExtend:
    case SYSTEM_INFORMATION_CLASS::SystemSessionProcessInformation:
    case SYSTEM_INFORMATION_CLASS::SystemLoadGdiDriverInSystemSpace:
    case SYSTEM_INFORMATION_CLASS::SystemNumaProcessorMap:
    case SYSTEM_INFORMATION_CLASS::SystemPrefetcherInformation:
    case SYSTEM_INFORMATION_CLASS::SystemExtendedProcessInformation:
    case SYSTEM_INFORMATION_CLASS::SystemRecommendedSharedDataAlignment:
    case SYSTEM_INFORMATION_CLASS::SystemComPlusPackage:
    case SYSTEM_INFORMATION_CLASS::SystemNumaAvailableMemory:
    case SYSTEM_INFORMATION_CLASS::SystemProcessorPowerInformation:
    case SYSTEM_INFORMATION_CLASS::SystemEmulationBasicInformation:
    case SYSTEM_INFORMATION_CLASS::SystemEmulationProcessorInformation:
    case SYSTEM_INFORMATION_CLASS::SystemExtendedHandleInformation:
    case SYSTEM_INFORMATION_CLASS::SystemLostDelayedWriteInformation:
    case SYSTEM_INFORMATION_CLASS::SystemBigPoolInformation:
    case SYSTEM_INFORMATION_CLASS::SystemSessionPoolTagInformation:
    case SYSTEM_INFORMATION_CLASS::SystemSessionMappedViewInformation:
    case SYSTEM_INFORMATION_CLASS::SystemHotpatchInformation:
    case SYSTEM_INFORMATION_CLASS::SystemObjectSecurityMode:
    case SYSTEM_INFORMATION_CLASS::SystemWatchdogTimerHandler:
    case SYSTEM_INFORMATION_CLASS::SystemWatchdogTimerInformation:
    case SYSTEM_INFORMATION_CLASS::SystemLogicalProcessorInformation:
    case SYSTEM_INFORMATION_CLASS::SystemWow64SharedInformationObsolete:
    case SYSTEM_INFORMATION_CLASS::SystemRegisterFirmwareTableInformationHandler:
    case SYSTEM_INFORMATION_CLASS::SystemFirmwareTableInformation:
    case SYSTEM_INFORMATION_CLASS::SystemModuleInformationEx:
    case SYSTEM_INFORMATION_CLASS::SystemVerifierTriageInformation:
    case SYSTEM_INFORMATION_CLASS::SystemSuperfetchInformation:
    case SYSTEM_INFORMATION_CLASS::SystemMemoryListInformation:
    case SYSTEM_INFORMATION_CLASS::SystemFileCacheInformationEx:
    case SYSTEM_INFORMATION_CLASS::SystemThreadPriorityClientIdInformation:
    case SYSTEM_INFORMATION_CLASS::SystemProcessorIdleCycleTimeInformation:
    case SYSTEM_INFORMATION_CLASS::SystemVerifierCancellationInformation:
    case SYSTEM_INFORMATION_CLASS::SystemProcessorPowerInformationEx:
    case SYSTEM_INFORMATION_CLASS::SystemRefTraceInformation:
    case SYSTEM_INFORMATION_CLASS::SystemSpecialPoolInformation:
    case SYSTEM_INFORMATION_CLASS::SystemProcessIdInformation:
    case SYSTEM_INFORMATION_CLASS::SystemErrorPortInformation:
    case SYSTEM_INFORMATION_CLASS::SystemBootEnvironmentInformation:
    case SYSTEM_INFORMATION_CLASS::SystemHypervisorInformation:
    case SYSTEM_INFORMATION_CLASS::SystemVerifierInformationEx:
    case SYSTEM_INFORMATION_CLASS::SystemTimeZoneInformation:
    case SYSTEM_INFORMATION_CLASS::SystemImageFileExecutionOptionsInformation:
    case SYSTEM_INFORMATION_CLASS::SystemCoverageInformation:
    case SYSTEM_INFORMATION_CLASS::SystemPrefetchPatchInformation:
    case SYSTEM_INFORMATION_CLASS::SystemVerifierFaultsInformation:
    case SYSTEM_INFORMATION_CLASS::SystemSystemPartitionInformation:
    case SYSTEM_INFORMATION_CLASS::SystemSystemDiskInformation:
    case SYSTEM_INFORMATION_CLASS::SystemProcessorPerformanceDistribution:
    case SYSTEM_INFORMATION_CLASS::SystemNumaProximityNodeInformation:
    case SYSTEM_INFORMATION_CLASS::SystemDynamicTimeZoneInformation:
    case SYSTEM_INFORMATION_CLASS::SystemCodeIntegrityInformation:
    case SYSTEM_INFORMATION_CLASS::SystemProcessorMicrocodeUpdateInformation:
    case SYSTEM_INFORMATION_CLASS::SystemProcessorBrandString:
    case SYSTEM_INFORMATION_CLASS::SystemVirtualAddressInformation:
    case SYSTEM_INFORMATION_CLASS::SystemLogicalProcessorAndGroupInformation:
    case SYSTEM_INFORMATION_CLASS::SystemProcessorCycleTimeInformation:
    case SYSTEM_INFORMATION_CLASS::SystemStoreInformation:
    case SYSTEM_INFORMATION_CLASS::SystemRegistryAppendString:
    case SYSTEM_INFORMATION_CLASS::SystemAitSamplingValue:
    case SYSTEM_INFORMATION_CLASS::SystemVhdBootInformation:
    case SYSTEM_INFORMATION_CLASS::SystemCpuQuotaInformation:
    case SYSTEM_INFORMATION_CLASS::SystemNativeBasicInformation:
    case SYSTEM_INFORMATION_CLASS::SystemErrorPortTimeouts:
    case SYSTEM_INFORMATION_CLASS::SystemLowPriorityIoInformation:
    case SYSTEM_INFORMATION_CLASS::SystemBootEntropyInformation:
    case SYSTEM_INFORMATION_CLASS::SystemVerifierCountersInformation:
    case SYSTEM_INFORMATION_CLASS::SystemPagedPoolInformationEx:
    case SYSTEM_INFORMATION_CLASS::SystemSystemPtesInformationEx:
    case SYSTEM_INFORMATION_CLASS::SystemNodeDistanceInformation:
    case SYSTEM_INFORMATION_CLASS::SystemAcpiAuditInformation:
    case SYSTEM_INFORMATION_CLASS::SystemBasicPerformanceInformation:
    case SYSTEM_INFORMATION_CLASS::SystemQueryPerformanceCounterInformation:
    case SYSTEM_INFORMATION_CLASS::SystemSessionBigPoolInformation:
    case SYSTEM_INFORMATION_CLASS::SystemBootGraphicsInformation:
    case SYSTEM_INFORMATION_CLASS::SystemScrubPhysicalMemoryInformation:
    case SYSTEM_INFORMATION_CLASS::SystemBadPageInformation:
    case SYSTEM_INFORMATION_CLASS::SystemProcessorProfileControlArea:
    case SYSTEM_INFORMATION_CLASS::SystemCombinePhysicalMemoryInformation:
    case SYSTEM_INFORMATION_CLASS::SystemEntropyInterruptTimingInformation:
    case SYSTEM_INFORMATION_CLASS::SystemConsoleInformation:
    case SYSTEM_INFORMATION_CLASS::SystemPlatformBinaryInformation:
    case SYSTEM_INFORMATION_CLASS::SystemThrottleNotificationInformation:
    case SYSTEM_INFORMATION_CLASS::SystemHypervisorProcessorCountInformation:
    case SYSTEM_INFORMATION_CLASS::SystemDeviceDataInformation:
    case SYSTEM_INFORMATION_CLASS::SystemDeviceDataEnumerationInformation:
    case SYSTEM_INFORMATION_CLASS::SystemMemoryTopologyInformation:
    case SYSTEM_INFORMATION_CLASS::SystemMemoryChannelInformation:
    case SYSTEM_INFORMATION_CLASS::SystemBootLogoInformation:
    case SYSTEM_INFORMATION_CLASS::SystemProcessorPerformanceInformationEx:
    case SYSTEM_INFORMATION_CLASS::SystemSpare0:
    case SYSTEM_INFORMATION_CLASS::SystemSecureBootPolicyInformation:
    case SYSTEM_INFORMATION_CLASS::SystemPageFileInformationEx:
    case SYSTEM_INFORMATION_CLASS::SystemSecureBootInformation:
    case SYSTEM_INFORMATION_CLASS::SystemEntropyInterruptTimingRawInformation:
    case SYSTEM_INFORMATION_CLASS::SystemPortableWorkspaceEfiLauncherInformation:
    case SYSTEM_INFORMATION_CLASS::SystemFullProcessInformation:
        return true;
    case SYSTEM_INFORMATION_CLASS::SystemUnknownInformation:
        return false;
    }

    return false;
}

const std::string& to_string(SYSTEM_INFORMATION_CLASS infoClass) {
    const static std::string SystemBasicInformationStr = "SystemBasicInformation";
    const static std::string SystemProcessorInformationStr = "SystemProcessorInformation";
    const static std::string SystemPerformanceInformationStr = "SystemPerformanceInformation";
    const static std::string SystemTimeOfDayInformationStr = "SystemTimeOfDayInformation";
    const static std::string SystemPathInformationStr = "SystemPathInformation";
    const static std::string SystemProcessInformationStr = "SystemProcessInformation";
    const static std::string SystemCallCountInformationStr = "SystemCallCountInformation";
    const static std::string SystemDeviceInformationStr = "SystemDeviceInformation";
    const static std::string SystemProcessorPerformanceInformationStr =
        "SystemProcessorPerformanceInformation";
    const static std::string SystemFlagsInformationStr = "SystemFlagsInformation";
    const static std::string SystemCallTimeInformationStr = "SystemCallTimeInformation";
    const static std::string SystemModuleInformationStr = "SystemModuleInformation";
    const static std::string SystemLocksInformationStr = "SystemLocksInformation";
    const static std::string SystemStackTraceInformationStr = "SystemStackTraceInformation";
    const static std::string SystemPagedPoolInformationStr = "SystemPagedPoolInformation";
    const static std::string SystemNonPagedPoolInformationStr = "SystemNonPagedPoolInformation";
    const static std::string SystemHandleInformationStr = "SystemHandleInformation";
    const static std::string SystemObjectInformationStr = "SystemObjectInformation";
    const static std::string SystemPageFileInformationStr = "SystemPageFileInformation";
    const static std::string SystemVdmInstemulInformationStr = "SystemVdmInstemulInformation";
    const static std::string SystemVdmBopInformationStr = "SystemVdmBopInformation";
    const static std::string SystemFileCacheInformationStr = "SystemFileCacheInformation";
    const static std::string SystemPoolTagInformationStr = "SystemPoolTagInformation";
    const static std::string SystemInterruptInformationStr = "SystemInterruptInformation";
    const static std::string SystemDpcBehaviorInformationStr = "SystemDpcBehaviorInformation";
    const static std::string SystemFullMemoryInformationStr = "SystemFullMemoryInformation";
    const static std::string SystemLoadGdiDriverInformationStr = "SystemLoadGdiDriverInformation";
    const static std::string SystemUnloadGdiDriverInformationStr =
        "SystemUnloadGdiDriverInformation";
    const static std::string SystemTimeAdjustmentInformationStr = "SystemTimeAdjustmentInformation";
    const static std::string SystemSummaryMemoryInformationStr = "SystemSummaryMemoryInformation";
    const static std::string SystemMirrorMemoryInformationStr = "SystemMirrorMemoryInformation";
    const static std::string SystemPerformanceTraceInformationStr =
        "SystemPerformanceTraceInformation";
    const static std::string SystemCrashDumpInformationStr = "SystemCrashDumpInformation";
    const static std::string SystemExceptionInformationStr = "SystemExceptionInformation";
    const static std::string SystemCrashDumpStateInformationStr = "SystemCrashDumpStateInformation";
    const static std::string SystemKernelDebuggerInformationStr = "SystemKernelDebuggerInformation";
    const static std::string SystemContextSwitchInformationStr = "SystemContextSwitchInformation";
    const static std::string SystemRegistryQuotaInformationStr = "SystemRegistryQuotaInformation";
    const static std::string SystemExtendServiceTableInformationStr =
        "SystemExtendServiceTableInformation";
    const static std::string SystemPrioritySeperationStr = "SystemPrioritySeperation";
    const static std::string SystemVerifierAddDriverInformationStr =
        "SystemVerifierAddDriverInformation";
    const static std::string SystemVerifierRemoveDriverInformationStr =
        "SystemVerifierRemoveDriverInformation";
    const static std::string SystemProcessorIdleInformationStr = "SystemProcessorIdleInformation";
    const static std::string SystemLegacyDriverInformationStr = "SystemLegacyDriverInformation";
    const static std::string SystemCurrentTimeZoneInformationStr =
        "SystemCurrentTimeZoneInformation";
    const static std::string SystemLookasideInformationStr = "SystemLookasideInformation";
    const static std::string SystemTimeSlipNotificationStr = "SystemTimeSlipNotification";
    const static std::string SystemSessionCreateStr = "SystemSessionCreate";
    const static std::string SystemSessionDetachStr = "SystemSessionDetach";
    const static std::string SystemSessionInformationStr = "SystemSessionInformation";
    const static std::string SystemRangeStartInformationStr = "SystemRangeStartInformation";
    const static std::string SystemVerifierInformationStr = "SystemVerifierInformation";
    const static std::string SystemVerifierThunkExtendStr = "SystemVerifierThunkExtend";
    const static std::string SystemSessionProcessInformationStr = "SystemSessionProcessInformation";
    const static std::string SystemLoadGdiDriverInSystemSpaceStr =
        "SystemLoadGdiDriverInSystemSpace";
    const static std::string SystemNumaProcessorMapStr = "SystemNumaProcessorMap";
    const static std::string SystemPrefetcherInformationStr = "SystemPrefetcherInformation";
    const static std::string SystemExtendedProcessInformationStr =
        "SystemExtendedProcessInformation";
    const static std::string SystemRecommendedSharedDataAlignmentStr =
        "SystemRecommendedSharedDataAlignment";
    const static std::string SystemComPlusPackageStr = "SystemComPlusPackage";
    const static std::string SystemNumaAvailableMemoryStr = "SystemNumaAvailableMemory";
    const static std::string SystemProcessorPowerInformationStr = "SystemProcessorPowerInformation";
    const static std::string SystemEmulationBasicInformationStr = "SystemEmulationBasicInformation";
    const static std::string SystemEmulationProcessorInformationStr =
        "SystemEmulationProcessorInformation";
    const static std::string SystemExtendedHandleInformationStr = "SystemExtendedHandleInformation";
    const static std::string SystemLostDelayedWriteInformationStr =
        "SystemLostDelayedWriteInformation";
    const static std::string SystemBigPoolInformationStr = "SystemBigPoolInformation";
    const static std::string SystemSessionPoolTagInformationStr = "SystemSessionPoolTagInformation";
    const static std::string SystemSessionMappedViewInformationStr =
        "SystemSessionMappedViewInformation";
    const static std::string SystemHotpatchInformationStr = "SystemHotpatchInformation";
    const static std::string SystemObjectSecurityModeStr = "SystemObjectSecurityMode";
    const static std::string SystemWatchdogTimerHandlerStr = "SystemWatchdogTimerHandler";
    const static std::string SystemWatchdogTimerInformationStr = "SystemWatchdogTimerInformation";
    const static std::string SystemLogicalProcessorInformationStr =
        "SystemLogicalProcessorInformation";
    const static std::string SystemWow64SharedInformationObsoleteStr =
        "SystemWow64SharedInformationObsolete";
    const static std::string SystemRegisterFirmwareTableInformationHandlerStr =
        "SystemRegisterFirmwareTableInformationHandler";
    const static std::string SystemFirmwareTableInformationStr = "SystemFirmwareTableInformation";
    const static std::string SystemModuleInformationExStr = "SystemModuleInformationEx";
    const static std::string SystemVerifierTriageInformationStr = "SystemVerifierTriageInformation";
    const static std::string SystemSuperfetchInformationStr = "SystemSuperfetchInformation";
    const static std::string SystemMemoryListInformationStr = "SystemMemoryListInformation";
    const static std::string SystemFileCacheInformationExStr = "SystemFileCacheInformationEx";
    const static std::string SystemThreadPriorityClientIdInformationStr =
        "SystemThreadPriorityClientIdInformation";
    const static std::string SystemProcessorIdleCycleTimeInformationStr =
        "SystemProcessorIdleCycleTimeInformation";
    const static std::string SystemVerifierCancellationInformationStr =
        "SystemVerifierCancellationInformation";
    const static std::string SystemProcessorPowerInformationExStr =
        "SystemProcessorPowerInformationEx";
    const static std::string SystemRefTraceInformationStr = "SystemRefTraceInformation";
    const static std::string SystemSpecialPoolInformationStr = "SystemSpecialPoolInformation";
    const static std::string SystemProcessIdInformationStr = "SystemProcessIdInformation";
    const static std::string SystemErrorPortInformationStr = "SystemErrorPortInformation";
    const static std::string SystemBootEnvironmentInformationStr =
        "SystemBootEnvironmentInformation";
    const static std::string SystemHypervisorInformationStr = "SystemHypervisorInformation";
    const static std::string SystemVerifierInformationExStr = "SystemVerifierInformationEx";
    const static std::string SystemTimeZoneInformationStr = "SystemTimeZoneInformation";
    const static std::string SystemImageFileExecutionOptionsInformationStr =
        "SystemImageFileExecutionOptionsInformation";
    const static std::string SystemCoverageInformationStr = "SystemCoverageInformation";
    const static std::string SystemPrefetchPatchInformationStr = "SystemPrefetchPatchInformation";
    const static std::string SystemVerifierFaultsInformationStr = "SystemVerifierFaultsInformation";
    const static std::string SystemSystemPartitionInformationStr =
        "SystemSystemPartitionInformation";
    const static std::string SystemSystemDiskInformationStr = "SystemSystemDiskInformation";
    const static std::string SystemProcessorPerformanceDistributionStr =
        "SystemProcessorPerformanceDistribution";
    const static std::string SystemNumaProximityNodeInformationStr =
        "SystemNumaProximityNodeInformation";
    const static std::string SystemDynamicTimeZoneInformationStr =
        "SystemDynamicTimeZoneInformation";
    const static std::string SystemCodeIntegrityInformationStr = "SystemCodeIntegrityInformation";
    const static std::string SystemProcessorMicrocodeUpdateInformationStr =
        "SystemProcessorMicrocodeUpdateInformation";
    const static std::string SystemProcessorBrandStringStr = "SystemProcessorBrandString";
    const static std::string SystemVirtualAddressInformationStr = "SystemVirtualAddressInformation";
    const static std::string SystemLogicalProcessorAndGroupInformationStr =
        "SystemLogicalProcessorAndGroupInformation";
    const static std::string SystemProcessorCycleTimeInformationStr =
        "SystemProcessorCycleTimeInformation";
    const static std::string SystemStoreInformationStr = "SystemStoreInformation";
    const static std::string SystemRegistryAppendStringStr = "SystemRegistryAppendString";
    const static std::string SystemAitSamplingValueStr = "SystemAitSamplingValue";
    const static std::string SystemVhdBootInformationStr = "SystemVhdBootInformation";
    const static std::string SystemCpuQuotaInformationStr = "SystemCpuQuotaInformation";
    const static std::string SystemNativeBasicInformationStr = "SystemNativeBasicInformation";
    const static std::string SystemErrorPortTimeoutsStr = "SystemErrorPortTimeouts";
    const static std::string SystemLowPriorityIoInformationStr = "SystemLowPriorityIoInformation";
    const static std::string SystemBootEntropyInformationStr = "SystemBootEntropyInformation";
    const static std::string SystemVerifierCountersInformationStr =
        "SystemVerifierCountersInformation";
    const static std::string SystemPagedPoolInformationExStr = "SystemPagedPoolInformationEx";
    const static std::string SystemSystemPtesInformationExStr = "SystemSystemPtesInformationEx";
    const static std::string SystemNodeDistanceInformationStr = "SystemNodeDistanceInformation";
    const static std::string SystemAcpiAuditInformationStr = "SystemAcpiAuditInformation";
    const static std::string SystemBasicPerformanceInformationStr =
        "SystemBasicPerformanceInformation";
    const static std::string SystemQueryPerformanceCounterInformationStr =
        "SystemQueryPerformanceCounterInformation";
    const static std::string SystemSessionBigPoolInformationStr = "SystemSessionBigPoolInformation";
    const static std::string SystemBootGraphicsInformationStr = "SystemBootGraphicsInformation";
    const static std::string SystemScrubPhysicalMemoryInformationStr =
        "SystemScrubPhysicalMemoryInformation";
    const static std::string SystemBadPageInformationStr = "SystemBadPageInformation";
    const static std::string SystemProcessorProfileControlAreaStr =
        "SystemProcessorProfileControlArea";
    const static std::string SystemCombinePhysicalMemoryInformationStr =
        "SystemCombinePhysicalMemoryInformation";
    const static std::string SystemEntropyInterruptTimingInformationStr =
        "SystemEntropyInterruptTimingInformation";
    const static std::string SystemConsoleInformationStr = "SystemConsoleInformation";
    const static std::string SystemPlatformBinaryInformationStr = "SystemPlatformBinaryInformation";
    const static std::string SystemThrottleNotificationInformationStr =
        "SystemThrottleNotificationInformation";
    const static std::string SystemHypervisorProcessorCountInformationStr =
        "SystemHypervisorProcessorCountInformation";
    const static std::string SystemDeviceDataInformationStr = "SystemDeviceDataInformation";
    const static std::string SystemDeviceDataEnumerationInformationStr =
        "SystemDeviceDataEnumerationInformation";
    const static std::string SystemMemoryTopologyInformationStr = "SystemMemoryTopologyInformation";
    const static std::string SystemMemoryChannelInformationStr = "SystemMemoryChannelInformation";
    const static std::string SystemBootLogoInformationStr = "SystemBootLogoInformation";
    const static std::string SystemProcessorPerformanceInformationExStr =
        "SystemProcessorPerformanceInformationEx";
    const static std::string SystemSpare0Str = "SystemSpare0";
    const static std::string SystemSecureBootPolicyInformationStr =
        "SystemSecureBootPolicyInformation";
    const static std::string SystemPageFileInformationExStr = "SystemPageFileInformationEx";
    const static std::string SystemSecureBootInformationStr = "SystemSecureBootInformation";
    const static std::string SystemEntropyInterruptTimingRawInformationStr =
        "SystemEntropyInterruptTimingRawInformation";
    const static std::string SystemPortableWorkspaceEfiLauncherInformationStr =
        "SystemPortableWorkspaceEfiLauncherInformation";
    const static std::string SystemFullProcessInformationStr = "SystemFullProcessInformation";
    const static std::string SystemUnknownInformationStr = "SystemUnknownInformation";

    switch (infoClass) {
    case SYSTEM_INFORMATION_CLASS::SystemBasicInformation:
        return SystemBasicInformationStr;
    case SYSTEM_INFORMATION_CLASS::SystemProcessorInformation:
        return SystemProcessorInformationStr;
    case SYSTEM_INFORMATION_CLASS::SystemPerformanceInformation:
        return SystemPerformanceInformationStr;
    case SYSTEM_INFORMATION_CLASS::SystemTimeOfDayInformation:
        return SystemTimeOfDayInformationStr;
    case SYSTEM_INFORMATION_CLASS::SystemPathInformation:
        return SystemPathInformationStr;
    case SYSTEM_INFORMATION_CLASS::SystemProcessInformation:
        return SystemProcessInformationStr;
    case SYSTEM_INFORMATION_CLASS::SystemCallCountInformation:
        return SystemCallCountInformationStr;
    case SYSTEM_INFORMATION_CLASS::SystemDeviceInformation:
        return SystemDeviceInformationStr;
    case SYSTEM_INFORMATION_CLASS::SystemProcessorPerformanceInformation:
        return SystemProcessorPerformanceInformationStr;
    case SYSTEM_INFORMATION_CLASS::SystemFlagsInformation:
        return SystemFlagsInformationStr;
    case SYSTEM_INFORMATION_CLASS::SystemCallTimeInformation:
        return SystemCallTimeInformationStr;
    case SYSTEM_INFORMATION_CLASS::SystemModuleInformation:
        return SystemModuleInformationStr;
    case SYSTEM_INFORMATION_CLASS::SystemLocksInformation:
        return SystemLocksInformationStr;
    case SYSTEM_INFORMATION_CLASS::SystemStackTraceInformation:
        return SystemStackTraceInformationStr;
    case SYSTEM_INFORMATION_CLASS::SystemPagedPoolInformation:
        return SystemPagedPoolInformationStr;
    case SYSTEM_INFORMATION_CLASS::SystemNonPagedPoolInformation:
        return SystemNonPagedPoolInformationStr;
    case SYSTEM_INFORMATION_CLASS::SystemHandleInformation:
        return SystemHandleInformationStr;
    case SYSTEM_INFORMATION_CLASS::SystemObjectInformation:
        return SystemObjectInformationStr;
    case SYSTEM_INFORMATION_CLASS::SystemPageFileInformation:
        return SystemPageFileInformationStr;
    case SYSTEM_INFORMATION_CLASS::SystemVdmInstemulInformation:
        return SystemVdmInstemulInformationStr;
    case SYSTEM_INFORMATION_CLASS::SystemVdmBopInformation:
        return SystemVdmBopInformationStr;
    case SYSTEM_INFORMATION_CLASS::SystemFileCacheInformation:
        return SystemFileCacheInformationStr;
    case SYSTEM_INFORMATION_CLASS::SystemPoolTagInformation:
        return SystemPoolTagInformationStr;
    case SYSTEM_INFORMATION_CLASS::SystemInterruptInformation:
        return SystemInterruptInformationStr;
    case SYSTEM_INFORMATION_CLASS::SystemDpcBehaviorInformation:
        return SystemDpcBehaviorInformationStr;
    case SYSTEM_INFORMATION_CLASS::SystemFullMemoryInformation:
        return SystemFullMemoryInformationStr;
    case SYSTEM_INFORMATION_CLASS::SystemLoadGdiDriverInformation:
        return SystemLoadGdiDriverInformationStr;
    case SYSTEM_INFORMATION_CLASS::SystemUnloadGdiDriverInformation:
        return SystemUnloadGdiDriverInformationStr;
    case SYSTEM_INFORMATION_CLASS::SystemTimeAdjustmentInformation:
        return SystemTimeAdjustmentInformationStr;
    case SYSTEM_INFORMATION_CLASS::SystemSummaryMemoryInformation:
        return SystemSummaryMemoryInformationStr;
    case SYSTEM_INFORMATION_CLASS::SystemMirrorMemoryInformation:
        return SystemMirrorMemoryInformationStr;
    case SYSTEM_INFORMATION_CLASS::SystemPerformanceTraceInformation:
        return SystemPerformanceTraceInformationStr;
    case SYSTEM_INFORMATION_CLASS::SystemCrashDumpInformation:
        return SystemCrashDumpInformationStr;
    case SYSTEM_INFORMATION_CLASS::SystemExceptionInformation:
        return SystemExceptionInformationStr;
    case SYSTEM_INFORMATION_CLASS::SystemCrashDumpStateInformation:
        return SystemCrashDumpStateInformationStr;
    case SYSTEM_INFORMATION_CLASS::SystemKernelDebuggerInformation:
        return SystemKernelDebuggerInformationStr;
    case SYSTEM_INFORMATION_CLASS::SystemContextSwitchInformation:
        return SystemContextSwitchInformationStr;
    case SYSTEM_INFORMATION_CLASS::SystemRegistryQuotaInformation:
        return SystemRegistryQuotaInformationStr;
    case SYSTEM_INFORMATION_CLASS::SystemExtendServiceTableInformation:
        return SystemExtendServiceTableInformationStr;
    case SYSTEM_INFORMATION_CLASS::SystemPrioritySeperation:
        return SystemPrioritySeperationStr;
    case SYSTEM_INFORMATION_CLASS::SystemVerifierAddDriverInformation:
        return SystemVerifierAddDriverInformationStr;
    case SYSTEM_INFORMATION_CLASS::SystemVerifierRemoveDriverInformation:
        return SystemVerifierRemoveDriverInformationStr;
    case SYSTEM_INFORMATION_CLASS::SystemProcessorIdleInformation:
        return SystemProcessorIdleInformationStr;
    case SYSTEM_INFORMATION_CLASS::SystemLegacyDriverInformation:
        return SystemLegacyDriverInformationStr;
    case SYSTEM_INFORMATION_CLASS::SystemCurrentTimeZoneInformation:
        return SystemCurrentTimeZoneInformationStr;
    case SYSTEM_INFORMATION_CLASS::SystemLookasideInformation:
        return SystemLookasideInformationStr;
    case SYSTEM_INFORMATION_CLASS::SystemTimeSlipNotification:
        return SystemTimeSlipNotificationStr;
    case SYSTEM_INFORMATION_CLASS::SystemSessionCreate:
        return SystemSessionCreateStr;
    case SYSTEM_INFORMATION_CLASS::SystemSessionDetach:
        return SystemSessionDetachStr;
    case SYSTEM_INFORMATION_CLASS::SystemSessionInformation:
        return SystemSessionInformationStr;
    case SYSTEM_INFORMATION_CLASS::SystemRangeStartInformation:
        return SystemRangeStartInformationStr;
    case SYSTEM_INFORMATION_CLASS::SystemVerifierInformation:
        return SystemVerifierInformationStr;
    case SYSTEM_INFORMATION_CLASS::SystemVerifierThunkExtend:
        return SystemVerifierThunkExtendStr;
    case SYSTEM_INFORMATION_CLASS::SystemSessionProcessInformation:
        return SystemSessionProcessInformationStr;
    case SYSTEM_INFORMATION_CLASS::SystemLoadGdiDriverInSystemSpace:
        return SystemLoadGdiDriverInSystemSpaceStr;
    case SYSTEM_INFORMATION_CLASS::SystemNumaProcessorMap:
        return SystemNumaProcessorMapStr;
    case SYSTEM_INFORMATION_CLASS::SystemPrefetcherInformation:
        return SystemPrefetcherInformationStr;
    case SYSTEM_INFORMATION_CLASS::SystemExtendedProcessInformation:
        return SystemExtendedProcessInformationStr;
    case SYSTEM_INFORMATION_CLASS::SystemRecommendedSharedDataAlignment:
        return SystemRecommendedSharedDataAlignmentStr;
    case SYSTEM_INFORMATION_CLASS::SystemComPlusPackage:
        return SystemComPlusPackageStr;
    case SYSTEM_INFORMATION_CLASS::SystemNumaAvailableMemory:
        return SystemNumaAvailableMemoryStr;
    case SYSTEM_INFORMATION_CLASS::SystemProcessorPowerInformation:
        return SystemProcessorPowerInformationStr;
    case SYSTEM_INFORMATION_CLASS::SystemEmulationBasicInformation:
        return SystemEmulationBasicInformationStr;
    case SYSTEM_INFORMATION_CLASS::SystemEmulationProcessorInformation:
        return SystemEmulationProcessorInformationStr;
    case SYSTEM_INFORMATION_CLASS::SystemExtendedHandleInformation:
        return SystemExtendedHandleInformationStr;
    case SYSTEM_INFORMATION_CLASS::SystemLostDelayedWriteInformation:
        return SystemLostDelayedWriteInformationStr;
    case SYSTEM_INFORMATION_CLASS::SystemBigPoolInformation:
        return SystemBigPoolInformationStr;
    case SYSTEM_INFORMATION_CLASS::SystemSessionPoolTagInformation:
        return SystemSessionPoolTagInformationStr;
    case SYSTEM_INFORMATION_CLASS::SystemSessionMappedViewInformation:
        return SystemSessionMappedViewInformationStr;
    case SYSTEM_INFORMATION_CLASS::SystemHotpatchInformation:
        return SystemHotpatchInformationStr;
    case SYSTEM_INFORMATION_CLASS::SystemObjectSecurityMode:
        return SystemObjectSecurityModeStr;
    case SYSTEM_INFORMATION_CLASS::SystemWatchdogTimerHandler:
        return SystemWatchdogTimerHandlerStr;
    case SYSTEM_INFORMATION_CLASS::SystemWatchdogTimerInformation:
        return SystemWatchdogTimerInformationStr;
    case SYSTEM_INFORMATION_CLASS::SystemLogicalProcessorInformation:
        return SystemLogicalProcessorInformationStr;
    case SYSTEM_INFORMATION_CLASS::SystemWow64SharedInformationObsolete:
        return SystemWow64SharedInformationObsoleteStr;
    case SYSTEM_INFORMATION_CLASS::SystemRegisterFirmwareTableInformationHandler:
        return SystemRegisterFirmwareTableInformationHandlerStr;
    case SYSTEM_INFORMATION_CLASS::SystemFirmwareTableInformation:
        return SystemFirmwareTableInformationStr;
    case SYSTEM_INFORMATION_CLASS::SystemModuleInformationEx:
        return SystemModuleInformationExStr;
    case SYSTEM_INFORMATION_CLASS::SystemVerifierTriageInformation:
        return SystemVerifierTriageInformationStr;
    case SYSTEM_INFORMATION_CLASS::SystemSuperfetchInformation:
        return SystemSuperfetchInformationStr;
    case SYSTEM_INFORMATION_CLASS::SystemMemoryListInformation:
        return SystemMemoryListInformationStr;
    case SYSTEM_INFORMATION_CLASS::SystemFileCacheInformationEx:
        return SystemFileCacheInformationExStr;
    case SYSTEM_INFORMATION_CLASS::SystemThreadPriorityClientIdInformation:
        return SystemThreadPriorityClientIdInformationStr;
    case SYSTEM_INFORMATION_CLASS::SystemProcessorIdleCycleTimeInformation:
        return SystemProcessorIdleCycleTimeInformationStr;
    case SYSTEM_INFORMATION_CLASS::SystemVerifierCancellationInformation:
        return SystemVerifierCancellationInformationStr;
    case SYSTEM_INFORMATION_CLASS::SystemProcessorPowerInformationEx:
        return SystemProcessorPowerInformationExStr;
    case SYSTEM_INFORMATION_CLASS::SystemRefTraceInformation:
        return SystemRefTraceInformationStr;
    case SYSTEM_INFORMATION_CLASS::SystemSpecialPoolInformation:
        return SystemSpecialPoolInformationStr;
    case SYSTEM_INFORMATION_CLASS::SystemProcessIdInformation:
        return SystemProcessIdInformationStr;
    case SYSTEM_INFORMATION_CLASS::SystemErrorPortInformation:
        return SystemErrorPortInformationStr;
    case SYSTEM_INFORMATION_CLASS::SystemBootEnvironmentInformation:
        return SystemBootEnvironmentInformationStr;
    case SYSTEM_INFORMATION_CLASS::SystemHypervisorInformation:
        return SystemHypervisorInformationStr;
    case SYSTEM_INFORMATION_CLASS::SystemVerifierInformationEx:
        return SystemVerifierInformationExStr;
    case SYSTEM_INFORMATION_CLASS::SystemTimeZoneInformation:
        return SystemTimeZoneInformationStr;
    case SYSTEM_INFORMATION_CLASS::SystemImageFileExecutionOptionsInformation:
        return SystemImageFileExecutionOptionsInformationStr;
    case SYSTEM_INFORMATION_CLASS::SystemCoverageInformation:
        return SystemCoverageInformationStr;
    case SYSTEM_INFORMATION_CLASS::SystemPrefetchPatchInformation:
        return SystemPrefetchPatchInformationStr;
    case SYSTEM_INFORMATION_CLASS::SystemVerifierFaultsInformation:
        return SystemVerifierFaultsInformationStr;
    case SYSTEM_INFORMATION_CLASS::SystemSystemPartitionInformation:
        return SystemSystemPartitionInformationStr;
    case SYSTEM_INFORMATION_CLASS::SystemSystemDiskInformation:
        return SystemSystemDiskInformationStr;
    case SYSTEM_INFORMATION_CLASS::SystemProcessorPerformanceDistribution:
        return SystemProcessorPerformanceDistributionStr;
    case SYSTEM_INFORMATION_CLASS::SystemNumaProximityNodeInformation:
        return SystemNumaProximityNodeInformationStr;
    case SYSTEM_INFORMATION_CLASS::SystemDynamicTimeZoneInformation:
        return SystemDynamicTimeZoneInformationStr;
    case SYSTEM_INFORMATION_CLASS::SystemCodeIntegrityInformation:
        return SystemCodeIntegrityInformationStr;
    case SYSTEM_INFORMATION_CLASS::SystemProcessorMicrocodeUpdateInformation:
        return SystemProcessorMicrocodeUpdateInformationStr;
    case SYSTEM_INFORMATION_CLASS::SystemProcessorBrandString:
        return SystemProcessorBrandStringStr;
    case SYSTEM_INFORMATION_CLASS::SystemVirtualAddressInformation:
        return SystemVirtualAddressInformationStr;
    case SYSTEM_INFORMATION_CLASS::SystemLogicalProcessorAndGroupInformation:
        return SystemLogicalProcessorAndGroupInformationStr;
    case SYSTEM_INFORMATION_CLASS::SystemProcessorCycleTimeInformation:
        return SystemProcessorCycleTimeInformationStr;
    case SYSTEM_INFORMATION_CLASS::SystemStoreInformation:
        return SystemStoreInformationStr;
    case SYSTEM_INFORMATION_CLASS::SystemRegistryAppendString:
        return SystemRegistryAppendStringStr;
    case SYSTEM_INFORMATION_CLASS::SystemAitSamplingValue:
        return SystemAitSamplingValueStr;
    case SYSTEM_INFORMATION_CLASS::SystemVhdBootInformation:
        return SystemVhdBootInformationStr;
    case SYSTEM_INFORMATION_CLASS::SystemCpuQuotaInformation:
        return SystemCpuQuotaInformationStr;
    case SYSTEM_INFORMATION_CLASS::SystemNativeBasicInformation:
        return SystemNativeBasicInformationStr;
    case SYSTEM_INFORMATION_CLASS::SystemErrorPortTimeouts:
        return SystemErrorPortTimeoutsStr;
    case SYSTEM_INFORMATION_CLASS::SystemLowPriorityIoInformation:
        return SystemLowPriorityIoInformationStr;
    case SYSTEM_INFORMATION_CLASS::SystemBootEntropyInformation:
        return SystemBootEntropyInformationStr;
    case SYSTEM_INFORMATION_CLASS::SystemVerifierCountersInformation:
        return SystemVerifierCountersInformationStr;
    case SYSTEM_INFORMATION_CLASS::SystemPagedPoolInformationEx:
        return SystemPagedPoolInformationExStr;
    case SYSTEM_INFORMATION_CLASS::SystemSystemPtesInformationEx:
        return SystemSystemPtesInformationExStr;
    case SYSTEM_INFORMATION_CLASS::SystemNodeDistanceInformation:
        return SystemNodeDistanceInformationStr;
    case SYSTEM_INFORMATION_CLASS::SystemAcpiAuditInformation:
        return SystemAcpiAuditInformationStr;
    case SYSTEM_INFORMATION_CLASS::SystemBasicPerformanceInformation:
        return SystemBasicPerformanceInformationStr;
    case SYSTEM_INFORMATION_CLASS::SystemQueryPerformanceCounterInformation:
        return SystemQueryPerformanceCounterInformationStr;
    case SYSTEM_INFORMATION_CLASS::SystemSessionBigPoolInformation:
        return SystemSessionBigPoolInformationStr;
    case SYSTEM_INFORMATION_CLASS::SystemBootGraphicsInformation:
        return SystemBootGraphicsInformationStr;
    case SYSTEM_INFORMATION_CLASS::SystemScrubPhysicalMemoryInformation:
        return SystemScrubPhysicalMemoryInformationStr;
    case SYSTEM_INFORMATION_CLASS::SystemBadPageInformation:
        return SystemBadPageInformationStr;
    case SYSTEM_INFORMATION_CLASS::SystemProcessorProfileControlArea:
        return SystemProcessorProfileControlAreaStr;
    case SYSTEM_INFORMATION_CLASS::SystemCombinePhysicalMemoryInformation:
        return SystemCombinePhysicalMemoryInformationStr;
    case SYSTEM_INFORMATION_CLASS::SystemEntropyInterruptTimingInformation:
        return SystemEntropyInterruptTimingInformationStr;
    case SYSTEM_INFORMATION_CLASS::SystemConsoleInformation:
        return SystemConsoleInformationStr;
    case SYSTEM_INFORMATION_CLASS::SystemPlatformBinaryInformation:
        return SystemPlatformBinaryInformationStr;
    case SYSTEM_INFORMATION_CLASS::SystemThrottleNotificationInformation:
        return SystemThrottleNotificationInformationStr;
    case SYSTEM_INFORMATION_CLASS::SystemHypervisorProcessorCountInformation:
        return SystemHypervisorProcessorCountInformationStr;
    case SYSTEM_INFORMATION_CLASS::SystemDeviceDataInformation:
        return SystemDeviceDataInformationStr;
    case SYSTEM_INFORMATION_CLASS::SystemDeviceDataEnumerationInformation:
        return SystemDeviceDataEnumerationInformationStr;
    case SYSTEM_INFORMATION_CLASS::SystemMemoryTopologyInformation:
        return SystemMemoryTopologyInformationStr;
    case SYSTEM_INFORMATION_CLASS::SystemMemoryChannelInformation:
        return SystemMemoryChannelInformationStr;
    case SYSTEM_INFORMATION_CLASS::SystemBootLogoInformation:
        return SystemBootLogoInformationStr;
    case SYSTEM_INFORMATION_CLASS::SystemProcessorPerformanceInformationEx:
        return SystemProcessorPerformanceInformationExStr;
    case SYSTEM_INFORMATION_CLASS::SystemSpare0:
        return SystemSpare0Str;
    case SYSTEM_INFORMATION_CLASS::SystemSecureBootPolicyInformation:
        return SystemSecureBootPolicyInformationStr;
    case SYSTEM_INFORMATION_CLASS::SystemPageFileInformationEx:
        return SystemPageFileInformationExStr;
    case SYSTEM_INFORMATION_CLASS::SystemSecureBootInformation:
        return SystemSecureBootInformationStr;
    case SYSTEM_INFORMATION_CLASS::SystemEntropyInterruptTimingRawInformation:
        return SystemEntropyInterruptTimingRawInformationStr;
    case SYSTEM_INFORMATION_CLASS::SystemPortableWorkspaceEfiLauncherInformation:
        return SystemPortableWorkspaceEfiLauncherInformationStr;
    case SYSTEM_INFORMATION_CLASS::SystemFullProcessInformation:
        return SystemFullProcessInformationStr;
    case SYSTEM_INFORMATION_CLASS::SystemUnknownInformation:
        return SystemUnknownInformationStr;
    }

    return SystemUnknownInformationStr;
}

std::ostream& operator<<(std::ostream& os, SYSTEM_INFORMATION_CLASS information_class) {
    os << to_string(information_class);
    return os;
}

} // namespace nt
} // namespace windows
} // namespace introvirt
