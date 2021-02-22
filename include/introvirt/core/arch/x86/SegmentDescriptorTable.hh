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

#include "Segment.hh"

#include <introvirt/core/fwd.hh>
#include <introvirt/core/memory/GuestVirtualAddress.hh>
#include <introvirt/core/memory/guest_ptr.hh>

#include <cstdint>
#include <memory>
#include <vector>

namespace introvirt {

namespace x86 {

/**
 * @brief Class to parse a segment descriptor table
 */
class SegmentDescriptorTable final {
  public:
    /**
     * @brief Get an entry based on an index into the table
     *
     * @param idx The index into the table
     * @return Segment
     */
    Segment index(uint16_t idx) const;

    /**
     * @brief Get an entry based on the selector
     *
     * @param sel The selector to use
     * @return Segment
     */
    Segment selector(SegmentSelector sel) const;

    /**
     * @brief Get the number of entries
     *
     * @return The number of entries in the table
     */
    size_t count() const;

    /**
     * @brief Construct a new Gdt object
     *
     * @param base The base address of the table
     * @param limit The size of the table
     */
    SegmentDescriptorTable(const GuestVirtualAddress& base, uint32_t limit);

  private:
    const GuestVirtualAddress base_;
    const uint32_t limit_;
    guest_ptr<char[]> mapping_;
};

} // namespace x86
} // namespace introvirt
