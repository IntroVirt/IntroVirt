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

#include "windows/kernel/nt/structs/structs.hh"
#include "windows/kernel/nt/types/PEB_LDR_DATA_IMPL.hh"
#include "windows/kernel/nt/types/RTL_USER_PROCESS_PARAMETERS_IMPL.hh"
#include "windows/kernel/nt/types/UNICODE_STRING_IMPL.hh"

#include <introvirt/core/memory/guest_ptr.hh>
#include <introvirt/windows/kernel/nt/types/PEB.hh>

#include <optional>

namespace introvirt {
namespace windows {
namespace nt {

namespace structs {

template <typename PtrType>
constexpr size_t GdiHandleBufferSize() {
    if (std::is_same_v<PtrType, uint64_t>)
        return 60;
    if (std::is_same_v<PtrType, uint32_t>)
        return 34;
    return 0;
}

template <typename PtrType>
struct _PEB {
    uint8_t InheritedAddressSpace;
    uint8_t ReadImageFileExecOptions;
    uint8_t BeingDebugged;
    union {
        uint8_t BitField;
        struct {
            uint8_t ImageUsesLargePages : 1;
            uint8_t IsProtectedProcess : 1;
            uint8_t IsLegacyProcess : 1;
            uint8_t IsImageDynamicallyRelocated : 1;
            uint8_t SpareBits : 4;
        };
    };
    PtrType Mutant;
    PtrType ImageBaseAddress;
    PtrType Ldr;
    PtrType ProcessParameters;
    PtrType SubSystemData;
    PtrType ProcessHeap;
    PtrType FastPebLock;
    PtrType AtlThunkSListPtr;
    PtrType IFEOKey;
    uint32_t CrossProcessFlags;
    uint32_t ProcessInJob : 1;
    uint32_t ProcessInitializing : 1;
    uint32_t ReservedBits0 : 30;
    union {
        PtrType KernelCallbackTable;
        PtrType UserSharedInfoPtr;
    };
    uint32_t SystemReserved[1];
    uint32_t SpareUlong;
    PtrType FreeList;
    uint32_t TlsExpansionCounter;
    PtrType TlsBitmap;
    uint32_t TlsBitmapBits[2];
    PtrType ReadOnlySharedMemoryBase;
    PtrType HotpatchInformation;
    PtrType ReadOnlyStaticServerData;
    PtrType AnsiCodePageData;
    PtrType OemCodePageData;
    PtrType UnicodeCaseTableData;
    uint32_t NumberOfProcessors;
    uint32_t NtGlobalFlag;
    int64_t CriticalSectionTimeout;
    PtrType HeapSegmentReserve;
    PtrType HeapSegmentCommit;
    PtrType HeapDeCommitTotalFreeThreshold;
    PtrType HeapDeCommitFreeBlockThreshold;
    uint32_t NumberOfHeaps;
    uint32_t MaximumNumberOfHeaps;
    PtrType ProcessHeaps;
    PtrType GdiSharedHandleTable;
    PtrType ProcessStarterHelper;
    uint32_t GdiDCAttributeList;
    PtrType LoaderLock;
    uint32_t OSMajorVersion;
    uint32_t OSMinorVersion;
    uint16_t OSBuildNumber;
    uint16_t OSCSDVersion;
    uint32_t OSPlatformId;
    uint32_t ImageSubsystem;
    uint32_t ImageSubsystemMajorVersion;
    uint32_t ImageSubsystemMinorVersion;
    PtrType ActiveProcessAffinityMask;
    uint32_t GdiHandleBuffer[GdiHandleBufferSize<PtrType>()];
    PtrType PostProcessInitRoutine;
    PtrType TlsExpansionBitmap;
    uint32_t TlsExpansionBitmapBits[32];
    uint32_t SessionId;
    uint64_t AppCompatFlags;
    uint64_t AppCompatFlagsUser;
    PtrType pShimData;
    PtrType AppCompatInfo;
    _UNICODE_STRING<PtrType> CSDVersion;
} __attribute__((__aligned__(sizeof(PtrType)), __ms_struct__));

static_assert(offsetof(_PEB<uint32_t>, Mutant) == 0x4);
static_assert(offsetof(_PEB<uint64_t>, Mutant) == 0x8);

static_assert(offsetof(_PEB<uint32_t>, CriticalSectionTimeout) == 0x70);
static_assert(offsetof(_PEB<uint64_t>, CriticalSectionTimeout) == 0xC0);

static_assert(offsetof(_PEB<uint32_t>, ProcessStarterHelper) == 0x98);
static_assert(offsetof(_PEB<uint64_t>, ProcessStarterHelper) == 0x100);

static_assert(offsetof(_PEB<uint32_t>, HeapDeCommitTotalFreeThreshold) == 0x80);
static_assert(offsetof(_PEB<uint64_t>, HeapDeCommitTotalFreeThreshold) == 0xd8);

static_assert(offsetof(_PEB<uint32_t>, ActiveProcessAffinityMask) == 0xc0);
static_assert(offsetof(_PEB<uint64_t>, ActiveProcessAffinityMask) == 0x138);

static_assert(offsetof(_PEB<uint32_t>, pShimData) == 0x1e8);
static_assert(offsetof(_PEB<uint64_t>, pShimData) == 0x2d8);

static_assert(offsetof(_PEB<uint32_t>, CSDVersion) == 0x1f0);
static_assert(offsetof(_PEB<uint64_t>, CSDVersion) == 0x2e8);

} // namespace structs

template <typename PtrType>
class PEB_IMPL final : public PEB {
  public:
    GuestVirtualAddress ImageBaseAddress() const override;

    const PEB_LDR_DATA* Ldr() const override;
    PEB_LDR_DATA* Ldr() override;

    const RTL_USER_PROCESS_PARAMETERS* ProcessParameters() const override;
    RTL_USER_PROCESS_PARAMETERS* ProcessParameters() override;

    uint32_t OSMajorVersion() const override;

    uint32_t OSMinorVersion() const override;

    uint16_t OSBuildNumber() const override;

    uint16_t OSCSDVersion() const override;

    uint32_t OSPlatformId() const override;

    uint16_t ServicePackNumber() const override;

    uint16_t MinorServicePackNumber() const override;

    uint32_t NumberOfProcessors() const override;

    GuestVirtualAddress address() const override;

    bool BeingDebugged() const override;

    void BeingDebugged(bool BeingDebugged) override;

    PEB_IMPL(const GuestVirtualAddress& gva);

  private:
    const GuestVirtualAddress gva_;

    guest_ptr<structs::_PEB<PtrType>> data_;

    // TODO: We'll need to make these two use real structs for 32-on-64 compatibility
    mutable std::optional<PEB_LDR_DATA_IMPL<PtrType>> ldr;
    mutable std::optional<RTL_USER_PROCESS_PARAMETERS_IMPL<PtrType>> rtlUserProcessParams;
};

} // namespace nt
} // namespace windows
} // namespace introvirt