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

#include <introvirt/core/memory/guest_ptr.hh>
#include <introvirt/windows/pe/types/IMAGE_RELOCATION_SECTION.hh>

namespace introvirt {
namespace windows {
namespace pe {

namespace structs {

struct _IMAGE_BASE_RELOCATION {
    uint32_t VirtualAddress;
    uint32_t SizeOfBlock;
};

} // namespace structs

/*
 * TODO: We could map one giant section rather than doing it piece by piece.
 *
 * I also am not thrilled with returning a vector. It'd be nicer if the IMAGE_RELOCATION_DIRECTORY
 * itself was the container, and provided begin()/end(),length() etc.
 *
 */
class IMAGE_RELOCATION_SECTION_IMPL final : public IMAGE_RELOCATION_SECTION {
  public:
    const std::vector<IMAGE_BASE_RELOCATION>& relocations() const override { return relocations_; }

    IMAGE_RELOCATION_SECTION_IMPL(const GuestVirtualAddress& image_base,
                                  const GuestVirtualAddress& reloc_data_address,
                                  uint32_t reloc_data_size) {

        const GuestVirtualAddress reloc_data_limit = reloc_data_address + reloc_data_size;

        GuestVirtualAddress addr = reloc_data_address;
        while (addr < reloc_data_limit) {
            guest_ptr<structs::_IMAGE_BASE_RELOCATION> entry(addr);

            // ntoskrnl.exe seems to have a zero size_of_block. We can't move forward.
            if (entry->SizeOfBlock < sizeof(structs::_IMAGE_BASE_RELOCATION))
                break;

            const uint32_t num_words =
                (entry->SizeOfBlock - sizeof(structs::_IMAGE_BASE_RELOCATION)) / sizeof(uint16_t);

            const GuestVirtualAddress pdata = addr + sizeof(structs::_IMAGE_BASE_RELOCATION);

            // Map in all of the data
            guest_ptr<uint16_t[]> data(pdata, num_words);
            for (unsigned int i = 0; i < num_words; ++i) {
                const GuestVirtualAddress reloc_address =
                    image_base + entry->VirtualAddress + (data[i] & 0xFFF);

                const uint8_t flags = data[i] >> 12;
                RelocationType type = static_cast<RelocationType>(flags);

                if (type == RelocationType::IMAGE_REL_BASED_ABSOLUTE) {
                    if ((data[i] & 0xFFF) == 0)
                        continue;
                }

                IMAGE_BASE_RELOCATION relocation_entry;
                relocation_entry.type = type;
                relocation_entry.reloc_address = reloc_address;
                relocations_.push_back(relocation_entry);
            }

            addr += entry->SizeOfBlock;
        }
    }

  private:
    std::vector<IMAGE_BASE_RELOCATION> relocations_;
};

} // namespace pe
} // namespace windows
} // namespace introvirt