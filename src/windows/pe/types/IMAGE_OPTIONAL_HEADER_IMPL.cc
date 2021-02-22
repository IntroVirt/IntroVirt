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
#include "IMAGE_OPTIONAL_HEADER_IMPL.hh"
#include "IMAGE_FILE_HEADER_IMPL.hh"

#include <introvirt/windows/pe/exception/PeException.hh>

namespace introvirt {
namespace windows {
namespace pe {

static constexpr uint16_t IMAGE_NT_OPTIONAL_HDR32_MAGIC = 0x10b;
static constexpr uint16_t IMAGE_NT_OPTIONAL_HDR64_MAGIC = 0x20b;

std::unique_ptr<IMAGE_OPTIONAL_HEADER>
IMAGE_OPTIONAL_HEADER::make_unique(const GuestVirtualAddress& image_base,
                                   const IMAGE_FILE_HEADER& file_header) {

    const GuestVirtualAddress poptional_header =
        static_cast<const IMAGE_FILE_HEADER_IMPL&>(file_header).address() +
        sizeof(structs::_IMAGE_FILE_HEADER);

    // Read the magic bytes at the start of the optional header to determine the type
    const uint64_t magic = *guest_ptr<uint16_t>(poptional_header);

    switch (magic) {
    case IMAGE_NT_OPTIONAL_HDR32_MAGIC:
        return std::make_unique<IMAGE_OPTIONAL_HEADER_IMPL<uint32_t>>(image_base, poptional_header);
    case IMAGE_NT_OPTIONAL_HDR64_MAGIC:
        return std::make_unique<IMAGE_OPTIONAL_HEADER_IMPL<uint64_t>>(image_base, poptional_header);
    default:
        throw PeException("Invalid PE Header Magic");
    }
}

} // namespace pe
} // namespace windows
} // namespace introvirt