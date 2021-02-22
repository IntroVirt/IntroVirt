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
#include "SYSTEM_INFORMATION_IMPL.hh"
#include "SYSTEM_BASIC_INFORMATION_IMPL.hh"
#include "SYSTEM_BASIC_PERFORMANCE_INFORMATION_IMPL.hh"
#include "SYSTEM_PERFORMANCE_INFORMATION_IMPL.hh"
#include "SYSTEM_PROCESSOR_INFORMATION_IMPL.hh"
#include "SYSTEM_PROCESS_INFORMATION_IMPL.hh"
#include "SYSTEM_TIMEOFDAY_INFORMATION_IMPL.hh"

#include <introvirt/windows/kernel/nt/NtKernel.hh>

namespace introvirt {
namespace windows {
namespace nt {

template <typename PtrType>
static std::unique_ptr<SYSTEM_INFORMATION>
make_unique_impl(SYSTEM_INFORMATION_CLASS information_class, const GuestVirtualAddress& gva,
                 uint32_t buffer_size) {

    switch (information_class) {
    case SYSTEM_INFORMATION_CLASS::SystemBasicInformation:
        return std::make_unique<SYSTEM_BASIC_INFORMATION_IMPL>(gva, buffer_size);
    case SYSTEM_INFORMATION_CLASS::SystemBasicPerformanceInformation:
        return std::make_unique<SYSTEM_BASIC_PERFORMANCE_INFORMATION_IMPL>(gva, buffer_size);
    case SYSTEM_INFORMATION_CLASS::SystemPerformanceInformation:
        return std::make_unique<SYSTEM_PERFORMANCE_INFORMATION_IMPL>(gva, buffer_size);
    case SYSTEM_INFORMATION_CLASS::SystemProcessorInformation:
        return std::make_unique<SYSTEM_PROCESSOR_INFORMATION_IMPL>(gva, buffer_size);
    case SYSTEM_INFORMATION_CLASS::SystemProcessInformation:
        return std::make_unique<SYSTEM_PROCESS_INFORMATION_IMPL<PtrType>>(gva, buffer_size);
    case SYSTEM_INFORMATION_CLASS::SystemTimeOfDayInformation:
        return std::make_unique<SYSTEM_TIMEOFDAY_INFORMATION_IMPL>(gva, buffer_size);
    }

    return std::make_unique<SYSTEM_INFORMATION_IMPL<>>(information_class, gva, buffer_size);
}

std::unique_ptr<SYSTEM_INFORMATION>
SYSTEM_INFORMATION::make_unique(const NtKernel& kernel, SYSTEM_INFORMATION_CLASS information_class,
                                const GuestVirtualAddress& gva, uint32_t buffer_size) {
    if (unlikely(buffer_size == 0))
        return nullptr;

    if (kernel.x64()) {
        return make_unique_impl<uint64_t>(information_class, gva, buffer_size);
    } else {
        return make_unique_impl<uint32_t>(information_class, gva, buffer_size);
    }
}

} // namespace nt
} // namespace windows
} // namespace introvirt