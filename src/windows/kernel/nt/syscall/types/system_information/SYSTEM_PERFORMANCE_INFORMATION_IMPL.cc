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
#include "SYSTEM_PERFORMANCE_INFORMATION_IMPL.hh"

#include <boost/io/ios_state.hpp>

namespace introvirt {
namespace windows {
namespace nt {

void SYSTEM_PERFORMANCE_INFORMATION_IMPL::write(std::ostream& os,
                                                const std::string& linePrefix) const {
    SYSTEM_PERFORMANCE_INFORMATION_IMPL_BASE::write(os, linePrefix);

    boost::io::ios_flags_saver ifs(os);
    os << std::dec;
    os << linePrefix << "IdleProcessTime: " << IdleProcessTime() << '\n';
    os << linePrefix << "IoReadTransferCount: " << IoReadTransferCount() << '\n';
    os << linePrefix << "IoWriteTransferCount: " << IoWriteTransferCount() << '\n';
    os << linePrefix << "IoOtherTransferCount: " << IoOtherTransferCount() << '\n';
    os << linePrefix << "IoReadOperationCount: " << IoReadOperationCount() << '\n';
    os << linePrefix << "IoWriteOperationCount: " << IoWriteOperationCount() << '\n';
    os << linePrefix << "IoOtherOperationCount: " << IoOtherOperationCount() << '\n';
    os << linePrefix << "AvailablePages: " << AvailablePages() << '\n';
    os << linePrefix << "CommittedPages: " << CommittedPages() << '\n';
    os << linePrefix << "CommitLimit: " << CommitLimit() << '\n';
    os << linePrefix << "PeakCommitment: " << PeakCommitment() << '\n';
    os << linePrefix << "PageFaultCount: " << PageFaultCount() << '\n';
    os << linePrefix << "CopyOnWriteCount: " << CopyOnWriteCount() << '\n';
    os << linePrefix << "TransitionCount: " << TransitionCount() << '\n';
    os << linePrefix << "CacheTransitionCount: " << CacheTransitionCount() << '\n';
    os << linePrefix << "DemandZeroCount: " << DemandZeroCount() << '\n';
    os << linePrefix << "PageReadCount: " << PageReadCount() << '\n';
    os << linePrefix << "PageReadIoCount: " << PageReadIoCount() << '\n';
    os << linePrefix << "CacheReadCount: " << CacheReadCount() << '\n';
    os << linePrefix << "CacheIoCount: " << CacheIoCount() << '\n';
    os << linePrefix << "DirtyPagesWriteCount: " << DirtyPagesWriteCount() << '\n';
    os << linePrefix << "DirtyWriteIoCount: " << DirtyWriteIoCount() << '\n';
    os << linePrefix << "MappedPagesWriteCount: " << MappedPagesWriteCount() << '\n';
    os << linePrefix << "MappedWriteIoCount: " << MappedWriteIoCount() << '\n';
    os << linePrefix << "PagedPoolPages: " << PagedPoolPages() << '\n';
    os << linePrefix << "NonPagedPoolPages: " << NonPagedPoolPages() << '\n';
    os << linePrefix << "PagedPoolAllocs: " << PagedPoolAllocs() << '\n';
    os << linePrefix << "PagedPoolFrees: " << PagedPoolFrees() << '\n';
    os << linePrefix << "NonPagedPoolAllocs: " << NonPagedPoolAllocs() << '\n';
    os << linePrefix << "NonPagedPoolFrees: " << NonPagedPoolFrees() << '\n';
    os << linePrefix << "FreeSystemPtes: " << FreeSystemPtes() << '\n';
    os << linePrefix << "ResidentSystemCodePage: " << ResidentSystemCodePage() << '\n';
    os << linePrefix << "TotalSystemDriverPages: " << TotalSystemDriverPages() << '\n';
    os << linePrefix << "TotalSystemCodePages: " << TotalSystemCodePages() << '\n';
    os << linePrefix << "NonPagedPoolLookasideHits: " << NonPagedPoolLookasideHits() << '\n';
    os << linePrefix << "PagedPoolLookasideHits: " << PagedPoolLookasideHits() << '\n';
    os << linePrefix << "AvailablePagedPoolPages: " << AvailablePagedPoolPages() << '\n';
    os << linePrefix << "ResidentSystemCachePage: " << ResidentSystemCachePage() << '\n';
    os << linePrefix << "ResidentPagedPoolPage: " << ResidentPagedPoolPage() << '\n';
    os << linePrefix << "ResidentSystemDriverPage: " << ResidentSystemDriverPage() << '\n';
    os << linePrefix << "CcFastReadNoWait: " << CcFastReadNoWait() << '\n';
    os << linePrefix << "CcFastReadWait: " << CcFastReadWait() << '\n';
    os << linePrefix << "CcFastReadResourceMiss: " << CcFastReadResourceMiss() << '\n';
    os << linePrefix << "CcFastReadNotPossible: " << CcFastReadNotPossible() << '\n';
    os << linePrefix << "CcFastMdlReadNoWait: " << CcFastMdlReadNoWait() << '\n';
    os << linePrefix << "CcFastMdlReadWait: " << CcFastMdlReadWait() << '\n';
    os << linePrefix << "CcFastMdlReadResourceMiss: " << CcFastMdlReadResourceMiss() << '\n';
    os << linePrefix << "CcFastMdlReadNotPossible: " << CcFastMdlReadNotPossible() << '\n';
    os << linePrefix << "CcMapDataNoWait: " << CcMapDataNoWait() << '\n';
    os << linePrefix << "CcMapDataWait: " << CcMapDataWait() << '\n';
    os << linePrefix << "CcMapDataNoWaitMiss: " << CcMapDataNoWaitMiss() << '\n';
    os << linePrefix << "CcMapDataWaitMiss: " << CcMapDataWaitMiss() << '\n';
    os << linePrefix << "CcPinMappedDataCount: " << CcPinMappedDataCount() << '\n';
    os << linePrefix << "CcPinReadNoWait: " << CcPinReadNoWait() << '\n';
    os << linePrefix << "CcPinReadWait: " << CcPinReadWait() << '\n';
    os << linePrefix << "CcPinReadNoWaitMiss: " << CcPinReadNoWaitMiss() << '\n';
    os << linePrefix << "CcPinReadWaitMiss: " << CcPinReadWaitMiss() << '\n';
    os << linePrefix << "CcCopyReadNoWait: " << CcCopyReadNoWait() << '\n';
    os << linePrefix << "CcCopyReadWait: " << CcCopyReadWait() << '\n';
    os << linePrefix << "CcCopyReadNoWaitMiss: " << CcCopyReadNoWaitMiss() << '\n';
    os << linePrefix << "CcCopyReadWaitMiss: " << CcCopyReadWaitMiss() << '\n';
    os << linePrefix << "CcMdlReadNoWait: " << CcMdlReadNoWait() << '\n';
    os << linePrefix << "CcMdlReadWait: " << CcMdlReadWait() << '\n';
    os << linePrefix << "CcMdlReadNoWaitMiss: " << CcMdlReadNoWaitMiss() << '\n';
    os << linePrefix << "CcMdlReadWaitMiss: " << CcMdlReadWaitMiss() << '\n';
    os << linePrefix << "CcReadAheadIos: " << CcReadAheadIos() << '\n';
    os << linePrefix << "CcLazyWriteIos: " << CcLazyWriteIos() << '\n';
    os << linePrefix << "CcLazyWritePages: " << CcLazyWritePages() << '\n';
    os << linePrefix << "CcDataFlushes: " << CcDataFlushes() << '\n';
    os << linePrefix << "CcDataPages: " << CcDataPages() << '\n';
    os << linePrefix << "ContextSwitches: " << ContextSwitches() << '\n';
    os << linePrefix << "FirstLevelTbFills: " << FirstLevelTbFills() << '\n';
    os << linePrefix << "SecondLevelTbFills: " << SecondLevelTbFills() << '\n';
    os << linePrefix << "SystemCalls: " << SystemCalls() << '\n';
}

Json::Value SYSTEM_PERFORMANCE_INFORMATION_IMPL::json() const {
    Json::Value result = SYSTEM_PERFORMANCE_INFORMATION_IMPL_BASE::json();
    result["IdleProcessTime"] = IdleProcessTime();
    result["IoReadTransferCount"] = IoReadTransferCount();
    result["IoWriteTransferCount"] = IoWriteTransferCount();
    result["IoOtherTransferCount"] = IoOtherTransferCount();
    result["IoReadOperationCount"] = IoReadOperationCount();
    result["IoWriteOperationCount"] = IoWriteOperationCount();
    result["IoOtherOperationCount"] = IoOtherOperationCount();
    result["AvailablePages"] = AvailablePages();
    result["CommittedPages"] = CommittedPages();
    result["CommitLimit"] = CommitLimit();
    result["PeakCommitment"] = PeakCommitment();
    result["PageFaultCount"] = PageFaultCount();
    result["CopyOnWriteCount"] = CopyOnWriteCount();
    result["TransitionCount"] = TransitionCount();
    result["CacheTransitionCount"] = CacheTransitionCount();
    result["DemandZeroCount"] = DemandZeroCount();
    result["PageReadCount"] = PageReadCount();
    result["PageReadIoCount"] = PageReadIoCount();
    result["CacheReadCount"] = CacheReadCount();
    result["CacheIoCount"] = CacheIoCount();
    result["DirtyPagesWriteCount"] = DirtyPagesWriteCount();
    result["DirtyWriteIoCount"] = DirtyWriteIoCount();
    result["MappedPagesWriteCount"] = MappedPagesWriteCount();
    result["MappedWriteIoCount"] = MappedWriteIoCount();
    result["PagedPoolPages"] = PagedPoolPages();
    result["NonPagedPoolPages"] = NonPagedPoolPages();
    result["PagedPoolAllocs"] = PagedPoolAllocs();
    result["PagedPoolFrees"] = PagedPoolFrees();
    result["NonPagedPoolAllocs"] = NonPagedPoolAllocs();
    result["NonPagedPoolFrees"] = NonPagedPoolFrees();
    result["FreeSystemPtes"] = FreeSystemPtes();
    result["ResidentSystemCodePage"] = ResidentSystemCodePage();
    result["TotalSystemDriverPages"] = TotalSystemDriverPages();
    result["TotalSystemCodePages"] = TotalSystemCodePages();
    result["NonPagedPoolLookasideHits"] = NonPagedPoolLookasideHits();
    result["PagedPoolLookasideHits"] = PagedPoolLookasideHits();
    result["AvailablePagedPoolPages"] = AvailablePagedPoolPages();
    result["ResidentSystemCachePage"] = ResidentSystemCachePage();
    result["ResidentPagedPoolPage"] = ResidentPagedPoolPage();
    result["ResidentSystemDriverPage"] = ResidentSystemDriverPage();
    result["CcFastReadNoWait"] = CcFastReadNoWait();
    result["CcFastReadWait"] = CcFastReadWait();
    result["CcFastReadResourceMiss"] = CcFastReadResourceMiss();
    result["CcFastReadNotPossible"] = CcFastReadNotPossible();
    result["CcFastMdlReadNoWait"] = CcFastMdlReadNoWait();
    result["CcFastMdlReadWait"] = CcFastMdlReadWait();
    result["CcFastMdlReadResourceMiss"] = CcFastMdlReadResourceMiss();
    result["CcFastMdlReadNotPossible"] = CcFastMdlReadNotPossible();
    result["CcMapDataNoWait"] = CcMapDataNoWait();
    result["CcMapDataWait"] = CcMapDataWait();
    result["CcMapDataNoWaitMiss"] = CcMapDataNoWaitMiss();
    result["CcMapDataWaitMiss"] = CcMapDataWaitMiss();
    result["CcPinMappedDataCount"] = CcPinMappedDataCount();
    result["CcPinReadNoWait"] = CcPinReadNoWait();
    result["CcPinReadWait"] = CcPinReadWait();
    result["CcPinReadNoWaitMiss"] = CcPinReadNoWaitMiss();
    result["CcPinReadWaitMiss"] = CcPinReadWaitMiss();
    result["CcCopyReadNoWait"] = CcCopyReadNoWait();
    result["CcCopyReadWait"] = CcCopyReadWait();
    result["CcCopyReadNoWaitMiss"] = CcCopyReadNoWaitMiss();
    result["CcCopyReadWaitMiss"] = CcCopyReadWaitMiss();
    result["CcMdlReadNoWait"] = CcMdlReadNoWait();
    result["CcMdlReadWait"] = CcMdlReadWait();
    result["CcMdlReadNoWaitMiss"] = CcMdlReadNoWaitMiss();
    result["CcMdlReadWaitMiss"] = CcMdlReadWaitMiss();
    result["CcReadAheadIos"] = CcReadAheadIos();
    result["CcLazyWriteIos"] = CcLazyWriteIos();
    result["CcLazyWritePages"] = CcLazyWritePages();
    result["CcDataFlushes"] = CcDataFlushes();
    result["CcDataPages"] = CcDataPages();
    result["ContextSwitches"] = ContextSwitches();
    result["FirstLevelTbFills"] = FirstLevelTbFills();
    result["SecondLevelTbFills"] = SecondLevelTbFills();
    result["SystemCalls"] = SystemCalls();
    return result;
}

} // namespace nt
} // namespace windows
} // namespace introvirt