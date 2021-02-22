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

#include <introvirt/core/arch/x86/Registers.hh>
#include <introvirt/core/arch/x86/SegmentDescriptorTable.hh>
#include <introvirt/core/domain/Vcpu.hh>
#include <introvirt/core/memory/guest_ptr.hh>

namespace introvirt {
namespace x86 {

/*
 * GdtEntry
 */

struct descriptor {
    uint16_t limit_bottom;
    uint16_t base_bottom;
    uint8_t base_mid;
    uint8_t type_attr;
    uint8_t lim_attr;
    uint8_t base_top;
} __attribute__((packed));

Segment SegmentDescriptorTable::index(uint16_t idx) const {
    return selector(SegmentSelector(idx << 3));
}

Segment SegmentDescriptorTable::selector(SegmentSelector sel) const {
    const int offset = sel.index() * sizeof(struct descriptor);

    assert(offset + sizeof(struct descriptor) <= limit_);

    // Get the descriptor from the table
    const auto* const dsc = reinterpret_cast<const struct descriptor*>(mapping_.get() + offset);

    // Figure out base/limit
    const uint64_t base = (static_cast<uint64_t>(dsc->base_top) << 24ull) |
                          (dsc->base_mid << 16ull) | dsc->base_bottom;

    const uint32_t limit =
        (static_cast<uint32_t>(dsc->lim_attr & 0xF) << 16ull) | dsc->limit_bottom;

    const uint8_t type = (dsc->type_attr & 0xF);
    const bool s = ((dsc->type_attr >> 4) & 1);
    const uint8_t dpl = ((dsc->type_attr >> 5) & 3);
    const bool p = ((dsc->type_attr >> 7) & 1);

    bool g = false;
    bool db = false;
    bool l = false;
    bool avl = false;

    // Construct a segment object
    if (s == 1) {
        g = dsc->lim_attr & 0x80;
        db = dsc->lim_attr & 0x40;
        l = dsc->lim_attr & 0x20;
        avl = dsc->lim_attr & 0x10;

        /*
        if ((type & 0x4) == 0) {
            // Data segment
        } else {
            // Code segment
        }
        */
    }

    return Segment(sel, base, limit, type, p, dpl, db, s, l, g, avl);
}

size_t SegmentDescriptorTable::count() const { return limit_ / sizeof(struct descriptor); }

SegmentDescriptorTable::SegmentDescriptorTable(const GuestVirtualAddress& base, uint32_t limit)
    : base_(base), limit_(limit), mapping_(base_, limit_) {}

} // namespace x86
} // namespace introvirt
