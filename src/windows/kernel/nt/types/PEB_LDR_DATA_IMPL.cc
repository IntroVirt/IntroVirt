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
#include "PEB_LDR_DATA_IMPL.hh"
#include "LDR_DATA_TABLE_ENTRY_IMPL.hh"

#include "../util/ListParser.hh"

namespace introvirt {
namespace windows {
namespace nt {

template <typename PtrType>
PEB_LDR_DATA_IMPL<PtrType>::PEB_LDR_DATA_IMPL(const GuestVirtualAddress& gva)
    : gva_(gva), data_(gva) {

    if (data_->Initialized == 0) {
        // Table not Initialized
        return;
    }

    // Let's walk them in load order
    const uint16_t InLoadOrderListOffset =
        offsetof(structs::_PEB_LDR_DATA<PtrType>, InLoadOrderModuleList);

    const uint16_t InLoadOrderLinksOffset =
        offsetof(structs::_LDR_DATA_TABLE_ENTRY<PtrType>, InLoadOrderLinks);

    const auto pInLoadOrderList = gva_ + InLoadOrderListOffset;

    std::vector<GuestVirtualAddress> entries =
        parse_list_ptrtype<PtrType>(pInLoadOrderList, InLoadOrderLinksOffset);

    for (const GuestVirtualAddress& entry : entries) {
        InLoadOrderList_.emplace_back(std::make_shared<LDR_DATA_TABLE_ENTRY_IMPL<PtrType>>(entry));
    }
}

template class PEB_LDR_DATA_IMPL<uint32_t>;
template class PEB_LDR_DATA_IMPL<uint64_t>;

} // namespace nt
} // namespace windows
} /* namespace introvirt */
