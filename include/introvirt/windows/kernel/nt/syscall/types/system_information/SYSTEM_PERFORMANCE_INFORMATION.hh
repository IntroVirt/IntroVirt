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

#include "SYSTEM_INFORMATION.hh"

namespace introvirt {
namespace windows {
namespace nt {

class SYSTEM_PERFORMANCE_INFORMATION : public SYSTEM_INFORMATION {
  public:
    virtual int64_t IdleProcessTime() const = 0;
    virtual int64_t IoReadTransferCount() const = 0;
    virtual int64_t IoWriteTransferCount() const = 0;
    virtual int64_t IoOtherTransferCount() const = 0;
    virtual uint32_t IoReadOperationCount() const = 0;
    virtual uint32_t IoWriteOperationCount() const = 0;
    virtual uint32_t IoOtherOperationCount() const = 0;

    /**
     * @returns The Physical Memory "Available" value in taskmgr
     */
    virtual uint32_t AvailablePages() const = 0;

    /**
     * @returns The Commit Charge "Total" value in taskmgr
     */

    virtual uint32_t CommittedPages() const = 0;

    /**
     * @returns The Commit Charge "Limit" value in taskmgr
     */
    virtual uint32_t CommitLimit() const = 0;

    /**
     * @returns The Commit Charge "Peak" value in taskmgr
     */
    virtual uint32_t PeakCommitment() const = 0;
    virtual uint32_t PageFaultCount() const = 0;
    virtual uint32_t CopyOnWriteCount() const = 0;
    virtual uint32_t TransitionCount() const = 0;
    virtual uint32_t CacheTransitionCount() const = 0;
    virtual uint32_t DemandZeroCount() const = 0;
    virtual uint32_t PageReadCount() const = 0;
    virtual uint32_t PageReadIoCount() const = 0;
    virtual uint32_t CacheReadCount() const = 0;
    virtual uint32_t CacheIoCount() const = 0;
    virtual uint32_t DirtyPagesWriteCount() const = 0;
    virtual uint32_t DirtyWriteIoCount() const = 0;
    virtual uint32_t MappedPagesWriteCount() const = 0;
    virtual uint32_t MappedWriteIoCount() const = 0;
    virtual uint32_t PagedPoolPages() const = 0;
    virtual uint32_t NonPagedPoolPages() const = 0;
    virtual uint32_t PagedPoolAllocs() const = 0;
    virtual uint32_t PagedPoolFrees() const = 0;
    virtual uint32_t NonPagedPoolAllocs() const = 0;
    virtual uint32_t NonPagedPoolFrees() const = 0;
    virtual uint32_t FreeSystemPtes() const = 0;
    virtual uint32_t ResidentSystemCodePage() const = 0;
    virtual uint32_t TotalSystemDriverPages() const = 0;
    virtual uint32_t TotalSystemCodePages() const = 0;
    virtual uint32_t NonPagedPoolLookasideHits() const = 0;
    virtual uint32_t PagedPoolLookasideHits() const = 0;
    virtual uint32_t AvailablePagedPoolPages() const = 0;
    virtual uint32_t ResidentSystemCachePage() const = 0;
    virtual uint32_t ResidentPagedPoolPage() const = 0;
    virtual uint32_t ResidentSystemDriverPage() const = 0;
    virtual uint32_t CcFastReadNoWait() const = 0;
    virtual uint32_t CcFastReadWait() const = 0;
    virtual uint32_t CcFastReadResourceMiss() const = 0;
    virtual uint32_t CcFastReadNotPossible() const = 0;
    virtual uint32_t CcFastMdlReadNoWait() const = 0;
    virtual uint32_t CcFastMdlReadWait() const = 0;
    virtual uint32_t CcFastMdlReadResourceMiss() const = 0;
    virtual uint32_t CcFastMdlReadNotPossible() const = 0;
    virtual uint32_t CcMapDataNoWait() const = 0;
    virtual uint32_t CcMapDataWait() const = 0;
    virtual uint32_t CcMapDataNoWaitMiss() const = 0;
    virtual uint32_t CcMapDataWaitMiss() const = 0;
    virtual uint32_t CcPinMappedDataCount() const = 0;
    virtual uint32_t CcPinReadNoWait() const = 0;
    virtual uint32_t CcPinReadWait() const = 0;
    virtual uint32_t CcPinReadNoWaitMiss() const = 0;
    virtual uint32_t CcPinReadWaitMiss() const = 0;
    virtual uint32_t CcCopyReadNoWait() const = 0;
    virtual uint32_t CcCopyReadWait() const = 0;
    virtual uint32_t CcCopyReadNoWaitMiss() const = 0;
    virtual uint32_t CcCopyReadWaitMiss() const = 0;
    virtual uint32_t CcMdlReadNoWait() const = 0;
    virtual uint32_t CcMdlReadWait() const = 0;
    virtual uint32_t CcMdlReadNoWaitMiss() const = 0;
    virtual uint32_t CcMdlReadWaitMiss() const = 0;
    virtual uint32_t CcReadAheadIos() const = 0;
    virtual uint32_t CcLazyWriteIos() const = 0;
    virtual uint32_t CcLazyWritePages() const = 0;
    virtual uint32_t CcDataFlushes() const = 0;
    virtual uint32_t CcDataPages() const = 0;
    virtual uint32_t ContextSwitches() const = 0;
    virtual uint32_t FirstLevelTbFills() const = 0;
    virtual uint32_t SecondLevelTbFills() const = 0;
    virtual uint32_t SystemCalls() const = 0;

    virtual void IdleProcessTime(int64_t IdleProcessTime) = 0;
    virtual void IoReadTransferCount(int64_t IoReadTransferCount) = 0;
    virtual void IoWriteTransferCount(int64_t IoWriteTransferCount) = 0;
    virtual void IoOtherTransferCount(int64_t IoOtherTransferCount) = 0;
    virtual void IoReadOperationCount(uint32_t IoReadOperationCount) = 0;
    virtual void IoWriteOperationCount(uint32_t IoWriteOperationCount) = 0;
    virtual void IoOtherOperationCount(uint32_t IoOtherOperationCount) = 0;
    virtual void AvailablePages(uint32_t AvailablePages) = 0;
    virtual void CommittedPages(uint32_t CommittedPages) = 0;
    virtual void CommitLimit(uint32_t CommitLimit) = 0;
    virtual void PeakCommitment(uint32_t PeakCommitment) = 0;
    virtual void PageFaultCount(uint32_t PageFaultCount) = 0;
    virtual void CopyOnWriteCount(uint32_t CopyOnWriteCount) = 0;
    virtual void TransitionCount(uint32_t TransitionCount) = 0;
    virtual void CacheTransitionCount(uint32_t CacheTransitionCount) = 0;
    virtual void DemandZeroCount(uint32_t DemandZeroCount) = 0;
    virtual void PageReadCount(uint32_t PageReadCount) = 0;
    virtual void PageReadIoCount(uint32_t PageReadIoCount) = 0;
    virtual void CacheReadCount(uint32_t CacheReadCount) = 0;
    virtual void CacheIoCount(uint32_t CacheIoCount) = 0;
    virtual void DirtyPagesWriteCount(uint32_t DirtyPagesWriteCount) = 0;
    virtual void DirtyWriteIoCount(uint32_t DirtyWriteIoCount) = 0;
    virtual void MappedPagesWriteCount(uint32_t MappedPagesWriteCount) = 0;
    virtual void MappedWriteIoCount(uint32_t MappedWriteIoCount) = 0;
    virtual void PagedPoolPages(uint32_t PagedPoolPages) = 0;
    virtual void NonPagedPoolPages(uint32_t NonPagedPoolPages) = 0;
    virtual void PagedPoolAllocs(uint32_t PagedPoolAllocs) = 0;
    virtual void PagedPoolFrees(uint32_t PagedPoolFrees) = 0;
    virtual void NonPagedPoolAllocs(uint32_t NonPagedPoolAllocs) = 0;
    virtual void NonPagedPoolFrees(uint32_t NonPagedPoolFrees) = 0;
    virtual void FreeSystemPtes(uint32_t FreeSystemPtes) = 0;
    virtual void ResidentSystemCodePage(uint32_t ResidentSystemCodePage) = 0;
    virtual void TotalSystemDriverPages(uint32_t TotalSystemDriverPages) = 0;
    virtual void TotalSystemCodePages(uint32_t TotalSystemCodePages) = 0;
    virtual void NonPagedPoolLookasideHits(uint32_t NonPagedPoolLookasideHits) = 0;
    virtual void PagedPoolLookasideHits(uint32_t PagedPoolLookasideHits) = 0;
    virtual void AvailablePagedPoolPages(uint32_t AvailablePagedPoolPages) = 0;
    virtual void ResidentSystemCachePage(uint32_t ResidentSystemCachePage) = 0;
    virtual void ResidentPagedPoolPage(uint32_t ResidentPagedPoolPage) = 0;
    virtual void ResidentSystemDriverPage(uint32_t ResidentSystemDriverPage) = 0;
    virtual void CcFastReadNoWait(uint32_t CcFastReadNoWait) = 0;
    virtual void CcFastReadWait(uint32_t CcFastReadWait) = 0;
    virtual void CcFastReadResourceMiss(uint32_t CcFastReadResourceMiss) = 0;
    virtual void CcFastReadNotPossible(uint32_t CcFastReadNotPossible) = 0;
    virtual void CcFastMdlReadNoWait(uint32_t CcFastMdlReadNoWait) = 0;
    virtual void CcFastMdlReadWait(uint32_t CcFastMdlReadWait) = 0;
    virtual void CcFastMdlReadResourceMiss(uint32_t CcFastMdlReadResourceMiss) = 0;
    virtual void CcFastMdlReadNotPossible(uint32_t CcFastMdlReadNotPossible) = 0;
    virtual void CcMapDataNoWait(uint32_t CcMapDataNoWait) = 0;
    virtual void CcMapDataWait(uint32_t CcMapDataWait) = 0;
    virtual void CcMapDataNoWaitMiss(uint32_t CcMapDataNoWaitMiss) = 0;
    virtual void CcMapDataWaitMiss(uint32_t CcMapDataWaitMiss) = 0;
    virtual void CcPinMappedDataCount(uint32_t CcPinMappedDataCount) = 0;
    virtual void CcPinReadNoWait(uint32_t CcPinReadNoWait) = 0;
    virtual void CcPinReadWait(uint32_t CcPinReadWait) = 0;
    virtual void CcPinReadNoWaitMiss(uint32_t CcPinReadNoWaitMiss) = 0;
    virtual void CcPinReadWaitMiss(uint32_t CcPinReadWaitMiss) = 0;
    virtual void CcCopyReadNoWait(uint32_t CcCopyReadNoWait) = 0;
    virtual void CcCopyReadWait(uint32_t CcCopyReadWait) = 0;
    virtual void CcCopyReadNoWaitMiss(uint32_t CcCopyReadNoWaitMiss) = 0;
    virtual void CcCopyReadWaitMiss(uint32_t CcCopyReadWaitMiss) = 0;
    virtual void CcMdlReadNoWait(uint32_t CcMdlReadNoWait) = 0;
    virtual void CcMdlReadWait(uint32_t CcMdlReadWait) = 0;
    virtual void CcMdlReadNoWaitMiss(uint32_t CcMdlReadNoWaitMiss) = 0;
    virtual void CcMdlReadWaitMiss(uint32_t CcMdlReadWaitMiss) = 0;
    virtual void CcReadAheadIos(uint32_t CcReadAheadIos) = 0;
    virtual void CcLazyWriteIos(uint32_t CcLazyWriteIos) = 0;
    virtual void CcLazyWritePages(uint32_t CcLazyWritePages) = 0;
    virtual void CcDataFlushes(uint32_t CcDataFlushes) = 0;
    virtual void CcDataPages(uint32_t CcDataPages) = 0;
    virtual void ContextSwitches(uint32_t ContextSwitches) = 0;
    virtual void FirstLevelTbFills(uint32_t FirstLevelTbFills) = 0;
    virtual void SecondLevelTbFills(uint32_t SecondLevelTbFills) = 0;
    virtual void SystemCalls(uint32_t SystemCalls) = 0;
};

} // namespace nt
} // namespace windows
} // namespace introvirt
