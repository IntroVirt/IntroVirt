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
#include <introvirt/util/compiler.hh>
#include <introvirt/windows/pe/types/IMAGE_RESOURCE_DATA_ENTRY.hh>

#include <log4cxx/logger.h>

namespace introvirt {
namespace windows {
namespace pe {

namespace structs {

struct _IMAGE_RESOURCE_DATA_ENTRY {
    uint32_t OffsetToData;
    uint32_t Size;
    uint32_t CodePage;
    uint32_t Reserved;
};

} // namespace structs

class IMAGE_RESOURCE_DATA_ENTRY_IMPL final : public IMAGE_RESOURCE_DATA_ENTRY {
  public:
    uint32_t OffsetToData() const { return data_->OffsetToData; }
    uint32_t Size() const { return data_->Size; }
    uint32_t CodePage() const { return data_->CodePage; }

    GuestVirtualAddress data_address() const { return image_base_ + OffsetToData(); }

    IMAGE_RESOURCE_DATA_ENTRY_IMPL(const GuestVirtualAddress& image_base,
                                   const GuestVirtualAddress& gva)
        : image_base_(image_base), data_(gva) {}

  private:
    const GuestVirtualAddress image_base_;
    guest_ptr<structs::_IMAGE_RESOURCE_DATA_ENTRY> data_;
};

} // namespace pe
} // namespace windows
} // namespace introvirt
