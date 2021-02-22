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
#include "IMAGE_RESOURCE_DIRECTORY_IMPL.hh"
#include "IMAGE_RESOURCE_DIRECTORY_ENTRY_IMPL.hh"

namespace introvirt {
namespace windows {
namespace pe {

IMAGE_RESOURCE_DIRECTORY_IMPL::IMAGE_RESOURCE_DIRECTORY_IMPL(
    const GuestVirtualAddress& pImageBase, const GuestVirtualAddress& pResourceBase,
    const GuestVirtualAddress& pResourceDirectory)

    : data_(pResourceDirectory) {

    // const bool isTopLevel = (pResourceDirectory == pResourceBase);

    // The directory entry elements that have name identifiers (rather than integer IDs) come
    // first in the array. So far, we don't care.

    const unsigned int total_entries = NumberOfNamedEntries() + NumberOfIdEntries();
    entries_.reserve(total_entries);

    const GuestVirtualAddress pFirstEntry =
        pResourceDirectory + sizeof(structs::_IMAGE_RESOURCE_DIRECTORY);

    for (unsigned int i = 0; i < total_entries; ++i) {
        const GuestVirtualAddress pEntry =
            pFirstEntry + (i * sizeof(structs::_IMAGE_RESOURCE_DIRECTORY_ENTRY));

        entries_.push_back(std::make_unique<const IMAGE_RESOURCE_DIRECTORY_ENTRY_IMPL>(
            pImageBase, pResourceBase, pEntry));

        if (const auto& entry = entries_.back(); !entry->NameIsString()) {
            id_to_entry_[entry->Id()] = entry.get();
        }
    }
}

} // namespace pe
} // namespace windows
} // namespace introvirt