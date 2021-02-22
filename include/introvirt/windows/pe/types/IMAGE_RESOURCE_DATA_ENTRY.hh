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

#include <introvirt/core/memory/GuestVirtualAddress.hh>

#include <cstdint>

namespace introvirt {
namespace windows {
namespace pe {

class IMAGE_RESOURCE_DATA_ENTRY {
  public:
    /**
     * @brief Get the relative offset from the base of the image to the data
     *
     * @return uint32_t
     */
    virtual uint32_t OffsetToData() const = 0;

    /**
     * @brief Get the size of the data
     *
     * @return uint32_t
     */
    virtual uint32_t Size() const = 0;

    /**
     * @brief Get the CodePage (TODO: What is this for?)
     *
     * @return uint32_t
     */
    virtual uint32_t CodePage() const = 0;

    /**
     * @brief Get the absolute address of the data
     *
     * @return GuestVirtualAddress
     */
    virtual GuestVirtualAddress data_address() const = 0;

    virtual ~IMAGE_RESOURCE_DATA_ENTRY() = default;
};

} // namespace pe
} // namespace windows
} // namespace introvirt
