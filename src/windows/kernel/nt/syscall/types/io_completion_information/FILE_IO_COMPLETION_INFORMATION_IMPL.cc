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

#include "FILE_IO_COMPLETION_INFORMATION_IMPL.hh"

#include <introvirt/windows/kernel/nt/NtKernel.hh>
#include <introvirt/windows/kernel/nt/syscall/types/io_completion_information/FILE_IO_COMPLETION_INFORMATION.hh>

#include <introvirt/core/exception/BufferTooSmallException.hh>
#include <introvirt/core/memory/guest_ptr.hh>

#include <boost/io/ios_state.hpp>

#include <cstddef>
#include <cstring>

namespace introvirt {
namespace windows {
namespace nt {

template <typename PtrType>
const IO_STATUS_BLOCK* FILE_IO_COMPLETION_INFORMATION_IMPL<PtrType>::IoStatusBlock() const {
    return &io_status_block_;
}

template <typename PtrType>
IO_STATUS_BLOCK* FILE_IO_COMPLETION_INFORMATION_IMPL<PtrType>::IoStatusBlock() {
    return &io_status_block_;
}

template <typename PtrType>
void FILE_IO_COMPLETION_INFORMATION_IMPL<PtrType>::write(std::ostream& os,
                                                         const std::string& linePrefix) const {
    boost::io::ios_flags_saver ifs(os);

    // !!TODO!! - WRITE FOR IoCompletionInformation NOT IMPLEMENTED
}

template <typename PtrType>
Json::Value FILE_IO_COMPLETION_INFORMATION_IMPL<PtrType>::json() const {
    Json::Value result;
    result["KeyContextPtr"] = KeyContextPtr();
    result["ApcContextPtr"] = ApcContextPtr();
    result["IoStatusBlock"] = IoStatusBlock()->json();
    return result;
}

std::unique_ptr<FILE_IO_COMPLETION_INFORMATION>
FILE_IO_COMPLETION_INFORMATION::make_unique(const NtKernel& kernel,
                                            const GuestVirtualAddress& gva) {
    if (kernel.x64()) {
        return std::make_unique<FILE_IO_COMPLETION_INFORMATION_IMPL<uint64_t>>(gva);
    } else {
        return std::make_unique<FILE_IO_COMPLETION_INFORMATION_IMPL<uint32_t>>(gva);
    }
}

} // namespace nt
} // namespace windows
} // namespace introvirt
