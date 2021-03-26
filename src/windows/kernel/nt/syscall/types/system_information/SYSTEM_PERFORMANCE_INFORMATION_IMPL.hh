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

#include "SYSTEM_INFORMATION_IMPL.hh"

#include <introvirt/windows/kernel/nt/syscall/types/system_information/SYSTEM_PERFORMANCE_INFORMATION.hh>

namespace introvirt {
namespace windows {
namespace nt {

namespace structs {

struct _SYSTEM_PERFORMANCE_INFORMATION {
    int64_t IdleProcessTime;            // Size=8 Offset=0
    int64_t IoReadTransferCount;        // Size=8 Offset=8
    int64_t IoWriteTransferCount;       // Size=8 Offset=16
    int64_t IoOtherTransferCount;       // Size=8 Offset=24
    uint32_t IoReadOperationCount;      // Size=4 Offset=32
    uint32_t IoWriteOperationCount;     // Size=4 Offset=36
    uint32_t IoOtherOperationCount;     // Size=4 Offset=40
    uint32_t AvailablePages;            // Size=4 Offset=44
    uint32_t CommittedPages;            // Size=4 Offset=48
    uint32_t CommitLimit;               // Size=4 Offset=52
    uint32_t PeakCommitment;            // Size=4 Offset=56
    uint32_t PageFaultCount;            // Size=4 Offset=60
    uint32_t CopyOnWriteCount;          // Size=4 Offset=64
    uint32_t TransitionCount;           // Size=4 Offset=68
    uint32_t CacheTransitionCount;      // Size=4 Offset=72
    uint32_t DemandZeroCount;           // Size=4 Offset=76
    uint32_t PageReadCount;             // Size=4 Offset=80
    uint32_t PageReadIoCount;           // Size=4 Offset=84
    uint32_t CacheReadCount;            // Size=4 Offset=88
    uint32_t CacheIoCount;              // Size=4 Offset=92
    uint32_t DirtyPagesWriteCount;      // Size=4 Offset=96
    uint32_t DirtyWriteIoCount;         // Size=4 Offset=100
    uint32_t MappedPagesWriteCount;     // Size=4 Offset=104
    uint32_t MappedWriteIoCount;        // Size=4 Offset=108
    uint32_t PagedPoolPages;            // Size=4 Offset=112
    uint32_t NonPagedPoolPages;         // Size=4 Offset=116
    uint32_t PagedPoolAllocs;           // Size=4 Offset=120
    uint32_t PagedPoolFrees;            // Size=4 Offset=124
    uint32_t NonPagedPoolAllocs;        // Size=4 Offset=128
    uint32_t NonPagedPoolFrees;         // Size=4 Offset=132
    uint32_t FreeSystemPtes;            // Size=4 Offset=136
    uint32_t ResidentSystemCodePage;    // Size=4 Offset=140
    uint32_t TotalSystemDriverPages;    // Size=4 Offset=144
    uint32_t TotalSystemCodePages;      // Size=4 Offset=148
    uint32_t NonPagedPoolLookasideHits; // Size=4 Offset=152
    uint32_t PagedPoolLookasideHits;    // Size=4 Offset=156
    uint32_t AvailablePagedPoolPages;   // Size=4 Offset=160
    uint32_t ResidentSystemCachePage;   // Size=4 Offset=164
    uint32_t ResidentPagedPoolPage;     // Size=4 Offset=168
    uint32_t ResidentSystemDriverPage;  // Size=4 Offset=172
    uint32_t CcFastReadNoWait;          // Size=4 Offset=176
    uint32_t CcFastReadWait;            // Size=4 Offset=180
    uint32_t CcFastReadResourceMiss;    // Size=4 Offset=184
    uint32_t CcFastReadNotPossible;     // Size=4 Offset=188
    uint32_t CcFastMdlReadNoWait;       // Size=4 Offset=192
    uint32_t CcFastMdlReadWait;         // Size=4 Offset=196
    uint32_t CcFastMdlReadResourceMiss; // Size=4 Offset=200
    uint32_t CcFastMdlReadNotPossible;  // Size=4 Offset=204
    uint32_t CcMapDataNoWait;           // Size=4 Offset=208
    uint32_t CcMapDataWait;             // Size=4 Offset=212
    uint32_t CcMapDataNoWaitMiss;       // Size=4 Offset=216
    uint32_t CcMapDataWaitMiss;         // Size=4 Offset=220
    uint32_t CcPinMappedDataCount;      // Size=4 Offset=224
    uint32_t CcPinReadNoWait;           // Size=4 Offset=228
    uint32_t CcPinReadWait;             // Size=4 Offset=232
    uint32_t CcPinReadNoWaitMiss;       // Size=4 Offset=236
    uint32_t CcPinReadWaitMiss;         // Size=4 Offset=240
    uint32_t CcCopyReadNoWait;          // Size=4 Offset=244
    uint32_t CcCopyReadWait;            // Size=4 Offset=248
    uint32_t CcCopyReadNoWaitMiss;      // Size=4 Offset=252
    uint32_t CcCopyReadWaitMiss;        // Size=4 Offset=256
    uint32_t CcMdlReadNoWait;           // Size=4 Offset=260
    uint32_t CcMdlReadWait;             // Size=4 Offset=264
    uint32_t CcMdlReadNoWaitMiss;       // Size=4 Offset=268
    uint32_t CcMdlReadWaitMiss;         // Size=4 Offset=272
    uint32_t CcReadAheadIos;            // Size=4 Offset=276
    uint32_t CcLazyWriteIos;            // Size=4 Offset=280
    uint32_t CcLazyWritePages;          // Size=4 Offset=284
    uint32_t CcDataFlushes;             // Size=4 Offset=288
    uint32_t CcDataPages;               // Size=4 Offset=292
    uint32_t ContextSwitches;           // Size=4 Offset=296
    uint32_t FirstLevelTbFills;         // Size=4 Offset=300
    uint32_t SecondLevelTbFills;        // Size=4 Offset=304
    uint32_t SystemCalls;               // Size=4 Offset=308
    // uint64_t CcTotalDirtyPages; // Size=8 Offset=312
    // uint64_t CcDirtyPageThreshold; // Size=8 Offset=320
    // int64_t ResidentAvailablePages; // Size=8 Offset=328
    // uint64_t SharedCommittedPages; // Size=8 Offset=336
};

// TODO: The structure is bigger on newer versions of Windows apparently

} // namespace structs

using SYSTEM_PERFORMANCE_INFORMATION_IMPL_BASE =
    SYSTEM_INFORMATION_IMPL<SYSTEM_PERFORMANCE_INFORMATION,
                            structs::_SYSTEM_PERFORMANCE_INFORMATION>;

class SYSTEM_PERFORMANCE_INFORMATION_IMPL final : public SYSTEM_PERFORMANCE_INFORMATION_IMPL_BASE {
  public:
    int64_t IdleProcessTime() const override { return this->ptr_->IdleProcessTime; }
    void IdleProcessTime(int64_t IdleProcessTime) override {
        this->ptr_->IdleProcessTime = IdleProcessTime;
    }

    int64_t IoReadTransferCount() const override { return this->ptr_->IoReadTransferCount; }
    void IoReadTransferCount(int64_t IoReadTransferCount) override {
        this->ptr_->IoReadTransferCount = IoReadTransferCount;
    }

    int64_t IoWriteTransferCount() const override { return this->ptr_->IoWriteTransferCount; }
    void IoWriteTransferCount(int64_t IoWriteTransferCount) override {
        this->ptr_->IoWriteTransferCount = IoWriteTransferCount;
    }

    int64_t IoOtherTransferCount() const override { return this->ptr_->IoOtherTransferCount; }
    void IoOtherTransferCount(int64_t IoOtherTransferCount) override {
        this->ptr_->IoOtherTransferCount = IoOtherTransferCount;
    }

    uint32_t IoReadOperationCount() const override { return this->ptr_->IoReadOperationCount; }
    void IoReadOperationCount(uint32_t IoReadOperationCount) override {
        this->ptr_->IoReadOperationCount = IoReadOperationCount;
    }

    uint32_t IoWriteOperationCount() const override { return this->ptr_->IoWriteOperationCount; }
    void IoWriteOperationCount(uint32_t IoWriteOperationCount) override {
        this->ptr_->IoWriteOperationCount = IoWriteOperationCount;
    }

    uint32_t IoOtherOperationCount() const override { return this->ptr_->IoOtherOperationCount; }
    void IoOtherOperationCount(uint32_t IoOtherOperationCount) override {
        this->ptr_->IoOtherOperationCount = IoOtherOperationCount;
    }

    uint32_t AvailablePages() const override { return this->ptr_->AvailablePages; }
    void AvailablePages(uint32_t AvailablePages) override {
        this->ptr_->AvailablePages = AvailablePages;
    }

    uint32_t CommittedPages() const override { return this->ptr_->CommittedPages; }
    void CommittedPages(uint32_t CommittedPages) override {
        this->ptr_->CommittedPages = CommittedPages;
    }

    uint32_t CommitLimit() const override { return this->ptr_->CommitLimit; }
    void CommitLimit(uint32_t CommitLimit) override { this->ptr_->CommitLimit = CommitLimit; }

    uint32_t PeakCommitment() const override { return this->ptr_->PeakCommitment; }
    void PeakCommitment(uint32_t PeakCommitment) override {
        this->ptr_->PeakCommitment = PeakCommitment;
    }

    uint32_t PageFaultCount() const override { return this->ptr_->PageFaultCount; }
    void PageFaultCount(uint32_t PageFaultCount) override {
        this->ptr_->PageFaultCount = PageFaultCount;
    }

    uint32_t CopyOnWriteCount() const override { return this->ptr_->CopyOnWriteCount; }
    void CopyOnWriteCount(uint32_t CopyOnWriteCount) override {
        this->ptr_->CopyOnWriteCount = CopyOnWriteCount;
    }

    uint32_t TransitionCount() const override { return this->ptr_->TransitionCount; }
    void TransitionCount(uint32_t TransitionCount) override {
        this->ptr_->TransitionCount = TransitionCount;
    }

    uint32_t CacheTransitionCount() const override { return this->ptr_->CacheTransitionCount; }
    void CacheTransitionCount(uint32_t CacheTransitionCount) override {
        this->ptr_->CacheTransitionCount = CacheTransitionCount;
    }

    uint32_t DemandZeroCount() const override { return this->ptr_->DemandZeroCount; }
    void DemandZeroCount(uint32_t DemandZeroCount) override {
        this->ptr_->DemandZeroCount = DemandZeroCount;
    }

    uint32_t PageReadCount() const override { return this->ptr_->PageReadCount; }
    void PageReadCount(uint32_t PageReadCount) override {
        this->ptr_->PageReadCount = PageReadCount;
    }

    uint32_t PageReadIoCount() const override { return this->ptr_->PageReadIoCount; }
    void PageReadIoCount(uint32_t PageReadIoCount) override {
        this->ptr_->PageReadIoCount = PageReadIoCount;
    }

    uint32_t CacheReadCount() const override { return this->ptr_->CacheReadCount; }
    void CacheReadCount(uint32_t CacheReadCount) override {
        this->ptr_->CacheReadCount = CacheReadCount;
    }

    uint32_t CacheIoCount() const override { return this->ptr_->CacheIoCount; }
    void CacheIoCount(uint32_t CacheIoCount) override { this->ptr_->CacheIoCount = CacheIoCount; }

    uint32_t DirtyPagesWriteCount() const override { return this->ptr_->DirtyPagesWriteCount; }
    void DirtyPagesWriteCount(uint32_t DirtyPagesWriteCount) override {
        this->ptr_->DirtyPagesWriteCount = DirtyPagesWriteCount;
    }

    uint32_t DirtyWriteIoCount() const override { return this->ptr_->DirtyWriteIoCount; }
    void DirtyWriteIoCount(uint32_t DirtyWriteIoCount) override {
        this->ptr_->DirtyWriteIoCount = DirtyWriteIoCount;
    }

    uint32_t MappedPagesWriteCount() const override { return this->ptr_->MappedPagesWriteCount; }
    void MappedPagesWriteCount(uint32_t MappedPagesWriteCount) override {
        this->ptr_->MappedPagesWriteCount = MappedPagesWriteCount;
    }

    uint32_t MappedWriteIoCount() const override { return this->ptr_->MappedWriteIoCount; }
    void MappedWriteIoCount(uint32_t MappedWriteIoCount) override {
        this->ptr_->MappedWriteIoCount = MappedWriteIoCount;
    }

    uint32_t PagedPoolPages() const override { return this->ptr_->PagedPoolPages; }
    void PagedPoolPages(uint32_t PagedPoolPages) override {
        this->ptr_->PagedPoolPages = PagedPoolPages;
    }

    uint32_t NonPagedPoolPages() const override { return this->ptr_->NonPagedPoolPages; }
    void NonPagedPoolPages(uint32_t NonPagedPoolPages) override {
        this->ptr_->NonPagedPoolPages = NonPagedPoolPages;
    }

    uint32_t PagedPoolAllocs() const override { return this->ptr_->PagedPoolAllocs; }
    void PagedPoolAllocs(uint32_t PagedPoolAllocs) override {
        this->ptr_->PagedPoolAllocs = PagedPoolAllocs;
    }

    uint32_t PagedPoolFrees() const override { return this->ptr_->PagedPoolFrees; }
    void PagedPoolFrees(uint32_t PagedPoolFrees) override {
        this->ptr_->PagedPoolFrees = PagedPoolFrees;
    }

    uint32_t NonPagedPoolAllocs() const override { return this->ptr_->NonPagedPoolAllocs; }
    void NonPagedPoolAllocs(uint32_t NonPagedPoolAllocs) override {
        this->ptr_->NonPagedPoolAllocs = NonPagedPoolAllocs;
    }

    uint32_t NonPagedPoolFrees() const override { return this->ptr_->NonPagedPoolFrees; }
    void NonPagedPoolFrees(uint32_t NonPagedPoolFrees) override {
        this->ptr_->NonPagedPoolFrees = NonPagedPoolFrees;
    }

    uint32_t FreeSystemPtes() const override { return this->ptr_->FreeSystemPtes; }
    void FreeSystemPtes(uint32_t FreeSystemPtes) override {
        this->ptr_->FreeSystemPtes = FreeSystemPtes;
    }

    uint32_t ResidentSystemCodePage() const override { return this->ptr_->ResidentSystemCodePage; }
    void ResidentSystemCodePage(uint32_t ResidentSystemCodePage) override {
        this->ptr_->ResidentSystemCodePage = ResidentSystemCodePage;
    }

    uint32_t TotalSystemDriverPages() const override { return this->ptr_->TotalSystemDriverPages; }
    void TotalSystemDriverPages(uint32_t TotalSystemDriverPages) override {
        this->ptr_->TotalSystemDriverPages = TotalSystemDriverPages;
    }

    uint32_t TotalSystemCodePages() const override { return this->ptr_->TotalSystemCodePages; }
    void TotalSystemCodePages(uint32_t TotalSystemCodePages) override {
        this->ptr_->TotalSystemCodePages = TotalSystemCodePages;
    }

    uint32_t NonPagedPoolLookasideHits() const override {
        return this->ptr_->NonPagedPoolLookasideHits;
    }
    void NonPagedPoolLookasideHits(uint32_t NonPagedPoolLookasideHits) override {
        this->ptr_->NonPagedPoolLookasideHits = NonPagedPoolLookasideHits;
    }

    uint32_t PagedPoolLookasideHits() const override { return this->ptr_->PagedPoolLookasideHits; }
    void PagedPoolLookasideHits(uint32_t PagedPoolLookasideHits) override {
        this->ptr_->PagedPoolLookasideHits = PagedPoolLookasideHits;
    }

    uint32_t AvailablePagedPoolPages() const override {
        return this->ptr_->AvailablePagedPoolPages;
    }
    void AvailablePagedPoolPages(uint32_t AvailablePagedPoolPages) override {
        this->ptr_->AvailablePagedPoolPages = AvailablePagedPoolPages;
    }

    uint32_t ResidentSystemCachePage() const override {
        return this->ptr_->ResidentSystemCachePage;
    }
    void ResidentSystemCachePage(uint32_t ResidentSystemCachePage) override {
        this->ptr_->ResidentSystemCachePage = ResidentSystemCachePage;
    }

    uint32_t ResidentPagedPoolPage() const override { return this->ptr_->ResidentPagedPoolPage; }
    void ResidentPagedPoolPage(uint32_t ResidentPagedPoolPage) override {
        this->ptr_->ResidentPagedPoolPage = ResidentPagedPoolPage;
    }

    uint32_t ResidentSystemDriverPage() const override {
        return this->ptr_->ResidentSystemDriverPage;
    }
    void ResidentSystemDriverPage(uint32_t ResidentSystemDriverPage) override {
        this->ptr_->ResidentSystemDriverPage = ResidentSystemDriverPage;
    }

    uint32_t CcFastReadNoWait() const override { return this->ptr_->CcFastReadNoWait; }
    void CcFastReadNoWait(uint32_t CcFastReadNoWait) override {
        this->ptr_->CcFastReadNoWait = CcFastReadNoWait;
    }

    uint32_t CcFastReadWait() const override { return this->ptr_->CcFastReadWait; }
    void CcFastReadWait(uint32_t CcFastReadWait) override {
        this->ptr_->CcFastReadWait = CcFastReadWait;
    }

    uint32_t CcFastReadResourceMiss() const override { return this->ptr_->CcFastReadResourceMiss; }
    void CcFastReadResourceMiss(uint32_t CcFastReadResourceMiss) override {
        this->ptr_->CcFastReadResourceMiss = CcFastReadResourceMiss;
    }

    uint32_t CcFastReadNotPossible() const override { return this->ptr_->CcFastReadNotPossible; }
    void CcFastReadNotPossible(uint32_t CcFastReadNotPossible) override {
        this->ptr_->CcFastReadNotPossible = CcFastReadNotPossible;
    }

    uint32_t CcFastMdlReadNoWait() const override { return this->ptr_->CcFastMdlReadNoWait; }
    void CcFastMdlReadNoWait(uint32_t CcFastMdlReadNoWait) override {
        this->ptr_->CcFastMdlReadNoWait = CcFastMdlReadNoWait;
    }

    uint32_t CcFastMdlReadWait() const override { return this->ptr_->CcFastMdlReadWait; }
    void CcFastMdlReadWait(uint32_t CcFastMdlReadWait) override {
        this->ptr_->CcFastMdlReadWait = CcFastMdlReadWait;
    }

    uint32_t CcFastMdlReadResourceMiss() const override {
        return this->ptr_->CcFastMdlReadResourceMiss;
    }
    void CcFastMdlReadResourceMiss(uint32_t CcFastMdlReadResourceMiss) override {
        this->ptr_->CcFastMdlReadResourceMiss = CcFastMdlReadResourceMiss;
    }

    uint32_t CcFastMdlReadNotPossible() const override {
        return this->ptr_->CcFastMdlReadNotPossible;
    }
    void CcFastMdlReadNotPossible(uint32_t CcFastMdlReadNotPossible) override {
        this->ptr_->CcFastMdlReadNotPossible = CcFastMdlReadNotPossible;
    }

    uint32_t CcMapDataNoWait() const override { return this->ptr_->CcMapDataNoWait; }
    void CcMapDataNoWait(uint32_t CcMapDataNoWait) override {
        this->ptr_->CcMapDataNoWait = CcMapDataNoWait;
    }

    uint32_t CcMapDataWait() const override { return this->ptr_->CcMapDataWait; }
    void CcMapDataWait(uint32_t CcMapDataWait) override {
        this->ptr_->CcMapDataWait = CcMapDataWait;
    }

    uint32_t CcMapDataNoWaitMiss() const override { return this->ptr_->CcMapDataNoWaitMiss; }
    void CcMapDataNoWaitMiss(uint32_t CcMapDataNoWaitMiss) override {
        this->ptr_->CcMapDataNoWaitMiss = CcMapDataNoWaitMiss;
    }

    uint32_t CcMapDataWaitMiss() const override { return this->ptr_->CcMapDataWaitMiss; }
    void CcMapDataWaitMiss(uint32_t CcMapDataWaitMiss) override {
        this->ptr_->CcMapDataWaitMiss = CcMapDataWaitMiss;
    }

    uint32_t CcPinMappedDataCount() const override { return this->ptr_->CcPinMappedDataCount; }
    void CcPinMappedDataCount(uint32_t CcPinMappedDataCount) override {
        this->ptr_->CcPinMappedDataCount = CcPinMappedDataCount;
    }

    uint32_t CcPinReadNoWait() const override { return this->ptr_->CcPinReadNoWait; }
    void CcPinReadNoWait(uint32_t CcPinReadNoWait) override {
        this->ptr_->CcPinReadNoWait = CcPinReadNoWait;
    }

    uint32_t CcPinReadWait() const override { return this->ptr_->CcPinReadWait; }
    void CcPinReadWait(uint32_t CcPinReadWait) override {
        this->ptr_->CcPinReadWait = CcPinReadWait;
    }

    uint32_t CcPinReadNoWaitMiss() const override { return this->ptr_->CcPinReadNoWaitMiss; }
    void CcPinReadNoWaitMiss(uint32_t CcPinReadNoWaitMiss) override {
        this->ptr_->CcPinReadNoWaitMiss = CcPinReadNoWaitMiss;
    }

    uint32_t CcPinReadWaitMiss() const override { return this->ptr_->CcPinReadWaitMiss; }
    void CcPinReadWaitMiss(uint32_t CcPinReadWaitMiss) override {
        this->ptr_->CcPinReadWaitMiss = CcPinReadWaitMiss;
    }

    uint32_t CcCopyReadNoWait() const override { return this->ptr_->CcCopyReadNoWait; }
    void CcCopyReadNoWait(uint32_t CcCopyReadNoWait) override {
        this->ptr_->CcCopyReadNoWait = CcCopyReadNoWait;
    }

    uint32_t CcCopyReadWait() const override { return this->ptr_->CcCopyReadWait; }
    void CcCopyReadWait(uint32_t CcCopyReadWait) override {
        this->ptr_->CcCopyReadWait = CcCopyReadWait;
    }

    uint32_t CcCopyReadNoWaitMiss() const override { return this->ptr_->CcCopyReadNoWaitMiss; }
    void CcCopyReadNoWaitMiss(uint32_t CcCopyReadNoWaitMiss) override {
        this->ptr_->CcCopyReadNoWaitMiss = CcCopyReadNoWaitMiss;
    }

    uint32_t CcCopyReadWaitMiss() const override { return this->ptr_->CcCopyReadWaitMiss; }
    void CcCopyReadWaitMiss(uint32_t CcCopyReadWaitMiss) override {
        this->ptr_->CcCopyReadWaitMiss = CcCopyReadWaitMiss;
    }

    uint32_t CcMdlReadNoWait() const override { return this->ptr_->CcMdlReadNoWait; }
    void CcMdlReadNoWait(uint32_t CcMdlReadNoWait) override {
        this->ptr_->CcMdlReadNoWait = CcMdlReadNoWait;
    }

    uint32_t CcMdlReadWait() const override { return this->ptr_->CcMdlReadWait; }
    void CcMdlReadWait(uint32_t CcMdlReadWait) override {
        this->ptr_->CcMdlReadWait = CcMdlReadWait;
    }

    uint32_t CcMdlReadNoWaitMiss() const override { return this->ptr_->CcMdlReadNoWaitMiss; }
    void CcMdlReadNoWaitMiss(uint32_t CcMdlReadNoWaitMiss) override {
        this->ptr_->CcMdlReadNoWaitMiss = CcMdlReadNoWaitMiss;
    }

    uint32_t CcMdlReadWaitMiss() const override { return this->ptr_->CcMdlReadWaitMiss; }
    void CcMdlReadWaitMiss(uint32_t CcMdlReadWaitMiss) override {
        this->ptr_->CcMdlReadWaitMiss = CcMdlReadWaitMiss;
    }

    uint32_t CcReadAheadIos() const override { return this->ptr_->CcReadAheadIos; }
    void CcReadAheadIos(uint32_t CcReadAheadIos) override {
        this->ptr_->CcReadAheadIos = CcReadAheadIos;
    }

    uint32_t CcLazyWriteIos() const override { return this->ptr_->CcLazyWriteIos; }
    void CcLazyWriteIos(uint32_t CcLazyWriteIos) override {
        this->ptr_->CcLazyWriteIos = CcLazyWriteIos;
    }

    uint32_t CcLazyWritePages() const override { return this->ptr_->CcLazyWritePages; }
    void CcLazyWritePages(uint32_t CcLazyWritePages) override {
        this->ptr_->CcLazyWritePages = CcLazyWritePages;
    }

    uint32_t CcDataFlushes() const override { return this->ptr_->CcDataFlushes; }
    void CcDataFlushes(uint32_t CcDataFlushes) override {
        this->ptr_->CcDataFlushes = CcDataFlushes;
    }

    uint32_t CcDataPages() const override { return this->ptr_->CcDataPages; }
    void CcDataPages(uint32_t CcDataPages) override { this->ptr_->CcDataPages = CcDataPages; }

    uint32_t ContextSwitches() const override { return this->ptr_->ContextSwitches; }
    void ContextSwitches(uint32_t ContextSwitches) override {
        this->ptr_->ContextSwitches = ContextSwitches;
    }

    uint32_t FirstLevelTbFills() const override { return this->ptr_->FirstLevelTbFills; }
    void FirstLevelTbFills(uint32_t FirstLevelTbFills) override {
        this->ptr_->FirstLevelTbFills = FirstLevelTbFills;
    }

    uint32_t SecondLevelTbFills() const override { return this->ptr_->SecondLevelTbFills; }
    void SecondLevelTbFills(uint32_t SecondLevelTbFills) override {
        this->ptr_->SecondLevelTbFills = SecondLevelTbFills;
    }

    uint32_t SystemCalls() const override { return this->ptr_->SystemCalls; }
    void SystemCalls(uint32_t SystemCalls) override { this->ptr_->SystemCalls = SystemCalls; }

    void write(std::ostream& os, const std::string& linePrefix = "") const override;
    Json::Value json() const override;

    SYSTEM_PERFORMANCE_INFORMATION_IMPL(const guest_ptr<void>& ptr, uint32_t buffer_size)
        : SYSTEM_PERFORMANCE_INFORMATION_IMPL_BASE(
              SYSTEM_INFORMATION_CLASS::SystemPerformanceInformation, ptr, buffer_size) {}
};

} // namespace nt
} // namespace windows
} // namespace introvirt