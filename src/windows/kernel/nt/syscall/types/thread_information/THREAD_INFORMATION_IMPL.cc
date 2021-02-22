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
#include "THREAD_INFORMATION_IMPL.hh"
#include "THREAD_BASE_PRIORITY_INFORMATION_IMPL.hh"
#include "THREAD_BASIC_INFORMATION_IMPL.hh"
#include "THREAD_IMPERSONATION_INFORMATION_IMPL.hh"
#include "THREAD_TIMES_INFORMATION_IMPL.hh"

#include <introvirt/core/exception/BufferTooSmallException.hh>
#include <introvirt/core/memory/guest_ptr.hh>
#include <introvirt/windows/kernel/nt/NtKernel.hh>

namespace introvirt {
namespace windows {
namespace nt {

template <typename PtrType>
static std::unique_ptr<THREAD_INFORMATION> make_unique_impl(THREAD_INFORMATION_CLASS info_class,
                                                            const GuestVirtualAddress& gva,
                                                            uint32_t buffer_size) {

    switch (info_class) {
    case THREAD_INFORMATION_CLASS::ThreadBasicInformation:
        return std::make_unique<THREAD_BASIC_INFORMATION_IMPL<PtrType>>(gva, buffer_size);
    case THREAD_INFORMATION_CLASS::ThreadImpersonationToken:
        return std::make_unique<THREAD_IMPERSONATION_INFORMATION_IMPL<PtrType>>(gva, buffer_size);
    case THREAD_INFORMATION_CLASS::ThreadTimes:
        return std::make_unique<THREAD_TIMES_INFORMATION_IMPL<PtrType>>(gva, buffer_size);
    case THREAD_INFORMATION_CLASS::ThreadBasePriority:
        return std::make_unique<THREAD_BASE_PRIORITY_INFORMATION_IMPL>(gva, buffer_size);
    }

    return std::make_unique<THREAD_INFORMATION_IMPL<>>(info_class, gva, buffer_size);
}

std::unique_ptr<THREAD_INFORMATION>
THREAD_INFORMATION::make_unique(const NtKernel& kernel, THREAD_INFORMATION_CLASS info_class,
                                const GuestVirtualAddress& gva, uint32_t buffer_size) {

    if (unlikely(buffer_size == 0))
        return nullptr;

    if (kernel.x64()) {
        return make_unique_impl<uint64_t>(info_class, gva, buffer_size);
    } else {
        return make_unique_impl<uint32_t>(info_class, gva, buffer_size);
    }
}

} /* namespace nt */
} /* namespace windows */
} /* namespace introvirt */
