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

#include "enums.hh"

#include <introvirt/core/memory/guest_ptr.hh>
#include <introvirt/windows/common/native_types.hh>

#include <cstdint>
#include <type_traits>

namespace introvirt {
namespace windows {
namespace nt {
namespace structs {

/*
 * Generic structures
 */
union _LARGE_INTEGER { // 0x8 bytes
    struct {           // offset 0x0
        ULONG LowPart; // offset   0x0 size   0x4
        LONG HighPart; // offset   0x4 size   0x4
    };                 // struct size 0x8
    LONGLONG QuadPart; // offset   0x0 size   0x8
};

union _ULARGE_INTEGER { // 0x8 bytes
    struct {            // offset 0x0
        ULONG LowPart;  // offset   0x0 size   0x4
        ULONG HighPart; // offset   0x4 size   0x4
    };                  // struct size 0x8
    ULONGLONG QuadPart; // offset   0x0 size   0x8
};

template <typename PtrType>
struct _LIST_ENTRY {
    PtrType /* _LIST_ENTRY<PtrType> */ Flink; // offset   0x0 size   0x4
    PtrType /* _LIST_ENTRY<PtrType> */ Blink; // offset   0x4 size   0x4
} __attribute__((packed, aligned(sizeof(PtrType))));

using _LIST_ENTRY32 = _LIST_ENTRY<uint32_t>;
using _LIST_ENTRY64 = _LIST_ENTRY<uint64_t>;

using LIST_ENTRY32 = _LIST_ENTRY<uint32_t>;
using LIST_ENTRY64 = _LIST_ENTRY<uint64_t>;

template <typename PtrType>
struct _SINGLE_LIST_ENTRY {                         // 0x4 bytes
    PtrType /* _SINGLE_LIST_ENTRY<PtrType> */ Next; // offset   0x0 size   0x4
} __attribute__((packed, aligned(sizeof(PtrType))));

using _SINGLE_LIST_ENTRY32 = _SINGLE_LIST_ENTRY<uint32_t>;
using _SINGLE_LIST_ENTRY64 = _SINGLE_LIST_ENTRY<uint64_t>;

struct _DBGKD_DEBUG_DATA_HEADER64 {
    _LIST_ENTRY<uint64_t> List;
    uint32_t OwnerTag;
    uint32_t Size;
};

struct _KDDEBUGGER_DATA64 {
    _DBGKD_DEBUG_DATA_HEADER64 Header;
    //
    // Base address of kernel image
    //

    ULONG64 KernBase;

    //
    // DbgBreakPointWithStatus is a function which takes an argument
    // and hits a breakpoint.  This field contains the address of the
    // breakpoint instruction.  When the debugger sees a breakpoint
    // at this address, it may retrieve the argument from the first
    // argument register, or on x86 the eax register.
    //

    ULONG64 BreakpointWithStatus; // address of breakpoint

    //
    // Address of the saved context record during a bugcheck
    //
    // N.B. This is an automatic in KeBugcheckEx's frame, and
    // is only valid after a bugcheck.
    //

    ULONG64 SavedContext;

    //
    // help for walking stacks with user callbacks:
    //

    //
    // The address of the thread structure is provided in the
    // WAIT_STATE_CHANGE packet.  This is the offset from the base of
    // the thread structure to the pointer to the kernel stack frame
    // for the currently active usermode callback.
    //

    UINT16 ThCallbackStack; // offset in thread data

    //
    // these values are offsets into that frame:
    //

    UINT16 NextCallback; // saved pointer to next callback frame
    UINT16 FramePointer; // saved frame pointer

    //
    // pad to a quad boundary
    //
    UINT16 PaeEnabled;

    //
    // Address of the kernel callout routine.
    //

    ULONG64 KiCallUserMode; // kernel routine

    //
    // Address of the usermode entry point for callbacks.
    //

    ULONG64 KeUserCallbackDispatcher; // address in ntdll

    //
    // Addresses of various kernel data structures and lists
    // that are of interest to the kernel debugger.
    //

    ULONG64 PsLoadedModuleList;
    ULONG64 PsActiveProcessHead;
    ULONG64 PspCidTable;

    ULONG64 ExpSystemResourcesList;
    ULONG64 ExpPagedPoolDescriptor;
    ULONG64 ExpNumberOfPagedPools;

    ULONG64 KeTimeIncrement;
    ULONG64 KeBugCheckCallbackListHead;
    ULONG64 KiBugcheckData;

    ULONG64 IopErrorLogListHead;

    ULONG64 ObpRootDirectoryObject;
    ULONG64 ObpTypeObjectType;

    ULONG64 MmSystemCacheStart;
    ULONG64 MmSystemCacheEnd;
    ULONG64 MmSystemCacheWs;

    ULONG64 MmPfnDatabase;
    ULONG64 MmSystemPtesStart;
    ULONG64 MmSystemPtesEnd;
    ULONG64 MmSubsectionBase;
    ULONG64 MmNumberOfPagingFiles;

    ULONG64 MmLowestPhysicalPage;
    ULONG64 MmHighestPhysicalPage;
    ULONG64 MmNumberOfPhysicalPages;

    ULONG64 MmMaximumNonPagedPoolInBytes;
    ULONG64 MmNonPagedSystemStart;
    ULONG64 MmNonPagedPoolStart;
    ULONG64 MmNonPagedPoolEnd;

    ULONG64 MmPagedPoolStart;
    ULONG64 MmPagedPoolEnd;
    ULONG64 MmPagedPoolInformation;
    ULONG64 MmPageSize;

    ULONG64 MmSizeOfPagedPoolInBytes;

    ULONG64 MmTotalCommitLimit;
    ULONG64 MmTotalCommittedPages;
    ULONG64 MmSharedCommit;
    ULONG64 MmDriverCommit;
    ULONG64 MmProcessCommit;
    ULONG64 MmPagedPoolCommit;
    ULONG64 MmExtendedCommit;

    ULONG64 MmZeroedPageListHead;
    ULONG64 MmFreePageListHead;
    ULONG64 MmStandbyPageListHead;
    ULONG64 MmModifiedPageListHead;
    ULONG64 MmModifiedNoWritePageListHead;
    ULONG64 MmAvailablePages;
    ULONG64 MmResidentAvailablePages;

    ULONG64 PoolTrackTable;
    ULONG64 NonPagedPoolDescriptor;

    ULONG64 MmHighestUserAddress;
    ULONG64 MmSystemRangeStart;
    ULONG64 MmUserProbeAddress;

    ULONG64 KdPrintCircularBuffer;
    ULONG64 KdPrintCircularBufferEnd;
    ULONG64 KdPrintWritePointer;
    ULONG64 KdPrintRolloverCount;

    ULONG64 MmLoadedUserImageList;

    // NT 5.1 Addition

    ULONG64 NtBuildLab;
    ULONG64 KiNormalSystemCall;

    // NT 5.0 hotfix addition

    ULONG64 KiProcessorBlock;
    ULONG64 MmUnloadedDrivers;
    ULONG64 MmLastUnloadedDriver;
    ULONG64 MmTriageActionTaken;
    ULONG64 MmSpecialPoolTag;
    ULONG64 KernelVerifier;
    ULONG64 MmVerifierData;
    ULONG64 MmAllocatedNonPagedPool;
    ULONG64 MmPeakCommitment;
    ULONG64 MmTotalCommitLimitMaximum;
    ULONG64 CmNtCSDVersion;

    // NT 5.1 Addition

    ULONG64 MmPhysicalMemoryBlock;
    ULONG64 MmSessionBase;
    ULONG64 MmSessionSize;
    ULONG64 MmSystemParentTablePage;

    // Server 2003 addition

    ULONG64 MmVirtualTranslationBase;

    UINT16 OffsetKThreadNextProcessor;
    UINT16 OffsetKThreadTeb;
    UINT16 OffsetKThreadKernelStack;
    UINT16 OffsetKThreadInitialStack;

    UINT16 OffsetKThreadApcProcess;
    UINT16 OffsetKThreadState;
    UINT16 OffsetKThreadBStore;
    UINT16 OffsetKThreadBStoreLimit;

    UINT16 SizeEProcess;
    UINT16 OffsetEprocessPeb;
    UINT16 OffsetEprocessParentCID;
    UINT16 OffsetEprocessDirectoryTableBase;

    UINT16 SizePrcb;
    UINT16 OffsetPrcbDpcRoutine;
    UINT16 OffsetPrcbCurrentThread;
    UINT16 OffsetPrcbMhz;

    UINT16 OffsetPrcbCpuType;
    UINT16 OffsetPrcbVendorString;
    UINT16 OffsetPrcbProcStateContext;
    UINT16 OffsetPrcbNumber;

    UINT16 SizeEThread;

    ULONG64 KdPrintCircularBufferPtr;
    ULONG64 KdPrintBufferSize;

    ULONG64 KeLoaderBlock;

    UINT16 SizePcr;
    UINT16 OffsetPcrSelfPcr;
    UINT16 OffsetPcrCurrentPrcb;
    UINT16 OffsetPcrContainedPrcb;

    UINT16 OffsetPcrInitialBStore;
    UINT16 OffsetPcrBStoreLimit;
    UINT16 OffsetPcrInitialStack;
    UINT16 OffsetPcrStackLimit;

    UINT16 OffsetPrcbPcrPage;
    UINT16 OffsetPrcbProcStateSpecialReg;
    UINT16 GdtR0Code;
    UINT16 GdtR0Data;

    UINT16 GdtR0Pcr;
    UINT16 GdtR3Code;
    UINT16 GdtR3Data;
    UINT16 GdtR3Teb;

    UINT16 GdtLdt;
    UINT16 GdtTss;
    UINT16 Gdt64R3CmCode;
    UINT16 Gdt64R3CmTeb;

    ULONG64 IopNumTriageDumpDataBlocks;
    ULONG64 IopTriageDumpDataBlocks;

    // Longhorn addition

    ULONG64 VfCrashDataBlock;
    ULONG64 MmBadPagesDetected;
    ULONG64 MmZeroedPageSingleBitErrorsDetected;
};

} // namespace structs
} // namespace nt
} // namespace windows
} // namespace introvirt
