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
#include "MM_SESSION_SPACE_IMPL.hh"
#include "windows/kernel/nt/NtKernelImpl.hh"

#include "../util/ListParser.hh"

#include <introvirt/windows/kernel/nt/NtKernel.hh>
#include <introvirt/windows/kernel/nt/types/objects/PROCESS.hh>

#include <log4cxx/logger.h>

#include <memory>

// static log4cxx::LoggerPtr
// logger(log4cxx::Logger::getLogger("introvirt.win.nt.mm_session_space"));

namespace introvirt {
namespace windows {
namespace nt {

template <typename PtrType>
GuestVirtualAddress MM_SESSION_SPACE_IMPL<PtrType>::address() const {
    return gva_;
}

template <typename PtrType>
std::vector<std::shared_ptr<const PROCESS>> MM_SESSION_SPACE_IMPL<PtrType>::process_list() const {
    std::vector<GuestVirtualAddress> addresses;

    addresses =
        parse_list_ptrtype<PtrType>(SessionProcListHeadAddress(), SessionProcessLinksOffset());

    // Get all of the process objects
    std::vector<std::shared_ptr<const PROCESS>> result;
    for (auto& addr : addresses) {
        result.emplace_back(kernel_.process(addr));
    }
    return result;
}

template <typename PtrType>
uint32_t MM_SESSION_SPACE_IMPL<PtrType>::SessionID() const {
    return mm_session_space->SessionId.get<uint32_t>(buffer);
}

template <typename PtrType>
uint16_t MM_SESSION_SPACE_IMPL<PtrType>::SessionProcessLinksOffset() const {
    return eprocess->SessionProcessLinks.offset();
}

template <typename PtrType>
GuestVirtualAddress MM_SESSION_SPACE_IMPL<PtrType>::SessionProcListHeadAddress() const {
    return address() + mm_session_space->ProcessList.offset();
}

template <typename PtrType>
MM_SESSION_SPACE_IMPL<PtrType>::MM_SESSION_SPACE_IMPL(const NtKernelImpl<PtrType>& kernel,
                                                      const GuestVirtualAddress& gva)
    : kernel_(kernel), gva_(gva) {
    // Load our structure offsets
    mm_session_space = LoadOffsets<structs::MM_SESSION_SPACE>(kernel);
    eprocess = LoadOffsets<structs::EPROCESS>(kernel);

    // Map in the structure. Doing one mapping is a lot cheaper than mapping every field.
    // We don't map in the 8k PoolTags array if it exists.
    const uint32_t buffer_size =
        ((mm_session_space->PoolTags.exists()) ? mm_session_space->PoolTags.offset()
                                               : mm_session_space->size());
    buffer.reset(gva, buffer_size);
}

template class MM_SESSION_SPACE_IMPL<uint32_t>;
template class MM_SESSION_SPACE_IMPL<uint64_t>;

} /* namespace nt */
} /* namespace windows */
} /* namespace introvirt */
