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

#include "../structs/structs.hh"

#include <introvirt/windows/kernel/nt/NtKernel.hh>

#include <log4cxx/logger.h>

#include <cstddef>
#include <cstdint>
#include <set>
#include <vector>

namespace introvirt {
namespace windows {
namespace nt {

static log4cxx::LoggerPtr
    listParserLogger(log4cxx::Logger::getLogger("introvirt.windows.kernel.nt.util.ListParser"));

/**
 * Parser utils for Window's LIST_ENTRY lists.
 * NOTE: The caller must free the resulting list entries, unless an exception is thrown!
 *
 * Example usage:
 *      void parseList(uint64_t virtual_address) {
 *          // Find the LIST_ENTRY offsets
 *          const static uint16_t InLoadOrderListOffset = offsetof(_PEB_LDR_DATA,
 * InLoadOrderModuleList); const static uint16_t InLoadOrderLinksOffset =
 * offsetof(_LDR_DATA_TABLE_ENTRY, InLoadOrderLinks);
 *
 *          std::vector<LDR_DATA_TABLE_ENTRY*> InLoadOrderList; // Can be any container
 * (std::vector, etc) parse_list<LDR_DATA_TABLE_ENTRY>(vcpu, wincfg, virtual_address +
 * InLoadOrderListOffset, InLoadOrderLinksOffset, std::back_inserter(InLoadOrderList));
 *
 *          // Do whatever ...
 *
 *          // Free the list contents when we're done.
 *          for(auto iter = InLoadOrderList.begin(); iter != InLoadOrderList.end(); ++iter) {
 *              delete *iter;
 *          }
 *      }
 */

template <class _Tp, typename PtrType, typename... _Args>
inline std::vector<std::shared_ptr<_Tp>>
parse_list_ptrtype(const NtKernel& kernel, const GuestVirtualAddress& list_head_address,
                   uint16_t listOffset, _Args&&... __args) {

    using _LIST_ENTRY = structs::_LIST_ENTRY<PtrType>;
    guest_ptr<_LIST_ENTRY> list(list_head_address);

    // Loops back to the list head, that's how we know we're at the end
    GuestVirtualAddress lastEntry = list_head_address.create(list->Blink);
    GuestVirtualAddress fLink = list_head_address.create(list->Flink);
    LOG4CXX_TRACE(listParserLogger, "Head Address " << list_head_address);
    LOG4CXX_TRACE(listParserLogger, "Last Entry: " << lastEntry);

    std::set<GuestVirtualAddress> visited;
    std::vector<std::shared_ptr<_Tp>> result;
    while (fLink) {
        // Keep track of which nodes we've already visited to prevent a circular infinite loop
        if (visited.count(fLink)) {
            LOG4CXX_TRACE(listParserLogger, "Exiting circular list");
            return result;
        }
        visited.insert(fLink);

        LOG4CXX_TRACE(listParserLogger, "Parsing " << fLink);
        guest_ptr<_LIST_ENTRY> entry(fLink);
        result.emplace_back(
            _Tp::make_shared(kernel, fLink - listOffset, std::forward<_Args>(__args)...));

        // Move on to the next entry
        if (fLink != lastEntry) {
            fLink = fLink.create(entry->Flink);
        } else {
            return result;
        }
    }

    // We shouldn't get here unless fLink was initially null
    return result;
}

template <class _Tp, typename... _Args>
inline std::vector<std::shared_ptr<_Tp>> parse_list(const NtKernel& kernel,
                                                    const GuestVirtualAddress& list_head_address,
                                                    uint16_t listOffset, _Args&&... __args) {
    if (kernel.x64()) {
        return parse_list_ptrtype<_Tp, uint64_t>(kernel, list_head_address, listOffset,
                                                 std::forward<_Args>(__args)...);
    }
    return parse_list_ptrtype<_Tp, uint32_t>(kernel, list_head_address, listOffset,
                                             std::forward<_Args>(__args)...);
}

/**
 * @returns A vector containing the address of each member of the list
 */
template <typename PtrType>
inline std::vector<GuestVirtualAddress>
parse_list_ptrtype(const GuestVirtualAddress& list_head_address, uint16_t list_offset) {
    using _LIST_ENTRY = structs::_LIST_ENTRY<PtrType>;
    guest_ptr<_LIST_ENTRY> list(list_head_address);

    // Loops back to the list head, that's how we know we're at the end
    const GuestVirtualAddress lastEntry = list_head_address.create(list->Blink);
    GuestVirtualAddress fLink = list_head_address.create(list->Flink);

    LOG4CXX_TRACE(listParserLogger, "Head Address: " << list_head_address);
    LOG4CXX_TRACE(listParserLogger, "Last Entry: " << lastEntry);

    std::set<GuestVirtualAddress> visited;
    std::vector<GuestVirtualAddress> result;

    while (fLink) {
        // Keep track of which nodes we've already visited to prevent a circular infinite loop
        if (visited.count(fLink)) {
            LOG4CXX_TRACE(listParserLogger, "Exiting circular list");
            return result;
        }
        visited.insert(fLink);
        LOG4CXX_TRACE(listParserLogger, "Parsing " << fLink);

        // Calculate the address of the start of the entry
        const GuestVirtualAddress pStructure = fLink - list_offset;
        // Add it to the list
        result.emplace_back(pStructure);

        // Move on to the next entry
        if (fLink != lastEntry) {
            // Map in the next entry and update fLink
            guest_ptr<_LIST_ENTRY> entry(fLink);
            fLink = fLink.create(entry->Flink);
        } else {
            return result;
        }
    }
    return result;
}

} // namespace nt
} // namespace windows
} // namespace introvirt
