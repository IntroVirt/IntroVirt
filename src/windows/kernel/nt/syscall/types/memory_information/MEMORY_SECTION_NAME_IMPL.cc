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
#include "MEMORY_SECTION_NAME_IMPL.hh"

#include <introvirt/core/exception/BufferTooSmallException.hh>
#include <introvirt/util/compiler.hh>
#include <introvirt/windows/WindowsGuest.hh>
#include <introvirt/windows/exception/InvalidStructureException.hh>

#include <cmath>

namespace introvirt {
namespace windows {
namespace nt {

template <typename PtrType>
void MEMORY_SECTION_NAME_IMPL<PtrType>::write(std::ostream& os,
                                              const std::string& linePrefix) const {

    MEMORY_SECTION_NAME_IMPL_BASE<PtrType>::write(os, linePrefix);
    os << linePrefix << "SectionFileName: " << SectionFileName() << '\n';
}

template <typename PtrType>
Json::Value MEMORY_SECTION_NAME_IMPL<PtrType>::json() const {
    Json::Value result = MEMORY_SECTION_NAME_IMPL_BASE<PtrType>::json();
    result["SectionFileName"] = SectionFileName();
    return result;
}

template <typename PtrType>
MEMORY_SECTION_NAME_IMPL<PtrType>::MEMORY_SECTION_NAME_IMPL(const guest_ptr<void>& ptr,
                                                            uint32_t buffer_size)
    : MEMORY_SECTION_NAME_IMPL_BASE<PtrType>(MEMORY_INFORMATION_CLASS::MemorySectionName, ptr,
                                             buffer_size) {

    /*
     * I chose to use WStr intead of a UNICODE_STRING here so that I'd have more control over the
     * maximum length, for the setter implementation.
     */
    const guest_ptr<void> pNameBuffer =
        ptr.clone(this->ptr_->SectionFileName.Buffer & 0xFFFFFFFFFFFFFFFELL);

    const guest_ptr<void> pBufferEnd = ptr + this->buffer_size_;

    if (unlikely(pNameBuffer < this->ptr_ || pNameBuffer >= pBufferEnd)) {
        throw InvalidStructureException("Name data is not part of buffer");
    }

    const uint16_t NameBufferMaxLength = pBufferEnd - pNameBuffer;
    const uint16_t NameBufferLength =
        std::min(NameBufferMaxLength, this->ptr_->SectionFileName.Length);

    // Decode the UNICODE_STRING data
    SectionFileName_.emplace(pNameBuffer, NameBufferMaxLength, NameBufferLength);
}

std::unique_ptr<MEMORY_SECTION_NAME> MEMORY_SECTION_NAME::make_unique(const NtKernel& kernel,
                                                                      const guest_ptr<void>& ptr,
                                                                      uint32_t buffer_size) {

    if (kernel.x64())
        return std::make_unique<MEMORY_SECTION_NAME_IMPL<uint64_t>>(ptr, buffer_size);
    else
        return std::make_unique<MEMORY_SECTION_NAME_IMPL<uint32_t>>(ptr, buffer_size);
}

template class MEMORY_SECTION_NAME_IMPL<uint32_t>;
template class MEMORY_SECTION_NAME_IMPL<uint64_t>;

} // namespace nt
} // namespace windows

namespace inject {

GuestAllocation<windows::nt::MEMORY_SECTION_NAME>::GuestAllocation() {
    using namespace windows;
    using namespace windows::nt;

    auto& domain = Domain::thread_local_domain();
    auto* guest = static_cast<WindowsGuest*>(domain.guest());
    introvirt_assert(guest != nullptr, "");

    if (guest->x64()) {
        constexpr uint32_t buffer_size = sizeof(nt::structs::_MEMORY_SECTION_NAME<uint64_t>);
        allocation_.emplace(buffer_size);
        value_ =
            std::make_unique<MEMORY_SECTION_NAME_IMPL<uint64_t>>(allocation_->ptr(), buffer_size);
    } else {
        constexpr uint32_t buffer_size = sizeof(nt::structs::_MEMORY_SECTION_NAME<uint32_t>);
        allocation_.emplace(buffer_size);
        value_ =
            std::make_unique<MEMORY_SECTION_NAME_IMPL<uint32_t>>(allocation_->ptr(), buffer_size);
    }
}

} // namespace inject
} // namespace introvirt