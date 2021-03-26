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
 * @returns A vector containing the address of each member of the list
 */
template <typename PtrType>
inline std::vector<guest_ptr<void>> parse_list_ptrtype(const guest_ptr<void>& plist_head,
                                                       uint16_t list_offset) {
    using _LIST_ENTRY = structs::_LIST_ENTRY<PtrType>;
    guest_ptr<_LIST_ENTRY> list(plist_head);

    // Loops back to the list head, that's how we know we're at the end
    guest_ptr<_LIST_ENTRY> lastEntry = list->Blink.get(plist_head);
    guest_ptr<_LIST_ENTRY> fLink = list->Flink.get(plist_head);

    LOG4CXX_TRACE(listParserLogger, "Head Address: " << plist_head);
    LOG4CXX_TRACE(listParserLogger, "Last Entry: " << lastEntry);

    std::set<guest_ptr<void>> visited;
    std::vector<guest_ptr<void>> result;
    while (fLink) {
        // Keep track of which nodes we've already visited to prevent a circular infinite loop
        if (visited.count(fLink)) {
            LOG4CXX_TRACE(listParserLogger, "Exiting circular list");
            return result;
        }
        visited.insert(fLink);

        LOG4CXX_TRACE(listParserLogger, "Parsing " << fLink);

        // The _LIST_ENTRY structure doesn't necessarily start at the begining of the struct.
        // Offset to find the base of it.
        guest_ptr<_LIST_ENTRY> entry(fLink);
        result.push_back(entry.clone(fLink.address() - list_offset));

        // Move on to the next entry
        if (fLink != lastEntry) {
            fLink = entry->Flink.get(fLink);
        } else {
            LOG4CXX_TRACE(listParserLogger, "Hit last entry " << fLink);
            return result;
        }
    }

    // We shouldn't get here unless fLink was initially null
    return result;
}

template <class _Tp, typename PtrType, typename... _Args>
inline std::vector<std::shared_ptr<_Tp>>
parse_list_ptrtype(const NtKernel& kernel, const guest_ptr<void>& plist_head, uint16_t list_offset,
                   _Args&&... __args) {

    std::vector<guest_ptr<void>> addresses = parse_list_ptrtype<PtrType>(plist_head, list_offset);

    std::vector<std::shared_ptr<_Tp>> result;
    for (const auto& entry : addresses) {
        result.emplace_back(_Tp::make_shared(kernel, entry, std::forward<_Args>(__args)...));
    }

    // We shouldn't get here unless fLink was initially null
    return result;
}

template <class _Tp, typename... _Args>
inline std::vector<std::shared_ptr<_Tp>> parse_list(const NtKernel& kernel,
                                                    const guest_ptr<void>& plist_head,
                                                    uint16_t listOffset, _Args&&... __args) {
    if (kernel.x64()) {
        return parse_list_ptrtype<_Tp, uint64_t>(kernel, plist_head, listOffset,
                                                 std::forward<_Args>(__args)...);
    }
    return parse_list_ptrtype<_Tp, uint32_t>(kernel, plist_head, listOffset,
                                             std::forward<_Args>(__args)...);
}

} // namespace nt
} // namespace windows
} // namespace introvirt
