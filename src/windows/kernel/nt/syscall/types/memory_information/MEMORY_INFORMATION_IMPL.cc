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
#include "MEMORY_INFORMATION_IMPL.hh"
#include "MEMORY_BASIC_INFORMATION_IMPL.hh"
#include "MEMORY_SECTION_NAME_IMPL.hh"

#include <introvirt/windows/kernel/nt/NtKernel.hh>

namespace introvirt {
namespace windows {
namespace nt {

template <typename PtrType>
std::unique_ptr<MEMORY_INFORMATION> make_unique_impl(MEMORY_INFORMATION_CLASS information_class,
                                                     const GuestVirtualAddress& gva,
                                                     uint32_t buffer_size) {

    // TODO(pape): Implement missing types
    switch (information_class) {
    case MEMORY_INFORMATION_CLASS::MemoryBasicInformation:
        return std::make_unique<MEMORY_BASIC_INFORMATION_IMPL<PtrType>>(gva, buffer_size);
    case MEMORY_INFORMATION_CLASS::MemorySectionName:
        return std::make_unique<MEMORY_SECTION_NAME_IMPL<PtrType>>(gva, buffer_size);
    }

    return std::make_unique<MEMORY_INFORMATION_IMPL<>>(information_class, gva, buffer_size);
}

std::unique_ptr<MEMORY_INFORMATION>
MEMORY_INFORMATION::make_unique(const NtKernel& kernel, MEMORY_INFORMATION_CLASS information_class,
                                const GuestVirtualAddress& gva, uint32_t buffer_size) {

    if (unlikely(buffer_size == 0))
        return nullptr;

    if (kernel.x64())
        return make_unique_impl<uint64_t>(information_class, gva, buffer_size);
    else
        return make_unique_impl<uint32_t>(information_class, gva, buffer_size);
}

} // namespace nt
} // namespace windows
} // namespace introvirt
