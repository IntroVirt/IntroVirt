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
#include "SECTION_INFORMATION_IMPL.hh"
#include "SECTION_BASIC_INFORMATION_IMPL.hh"
#include "SECTION_IMAGE_INFORMATION_IMPL.hh"
#include "SECTION_RELOCATION_INFORMATION_IMPL.hh"

#include <introvirt/windows/kernel/nt/NtKernel.hh>

namespace introvirt {
namespace windows {
namespace nt {

template <typename PtrType>
static std::unique_ptr<SECTION_INFORMATION>
make_unique_impl(SECTION_INFORMATION_CLASS information_class, const GuestVirtualAddress& gva,
                 uint32_t buffer_size) {

    switch (information_class) {
    case SECTION_INFORMATION_CLASS::SectionBasicInformation:
        return std::make_unique<SECTION_BASIC_INFORMATION_IMPL<PtrType>>(gva, buffer_size);
    case SECTION_INFORMATION_CLASS::SectionImageInformation:
        return std::make_unique<SECTION_IMAGE_INFORMATION_IMPL<PtrType>>(gva, buffer_size);
    case SECTION_INFORMATION_CLASS::SectionRelocationInformation:
        return std::make_unique<SECTION_RELOCATION_INFORMATION_IMPL<PtrType>>(gva, buffer_size);
    }

    return std::make_unique<SECTION_INFORMATION_IMPL<>>(information_class, gva, buffer_size);
}

std::unique_ptr<SECTION_INFORMATION>
SECTION_INFORMATION::make_unique(const NtKernel& kernel,
                                 SECTION_INFORMATION_CLASS information_class,
                                 const GuestVirtualAddress& gva, uint32_t buffer_size) {

    if (kernel.x64()) {
        return make_unique_impl<uint64_t>(information_class, gva, buffer_size);
    } else {
        return make_unique_impl<uint32_t>(information_class, gva, buffer_size);
    }
}

} // namespace nt
} // namespace windows
} // namespace introvirt