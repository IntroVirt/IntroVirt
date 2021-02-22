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

#include <introvirt/core/arch/x86/Idt.hh>

#include <introvirt/core/domain/Vcpu.hh>
#include <introvirt/core/memory/guest_ptr.hh>
#include <introvirt/util/compiler.hh>

namespace introvirt {
namespace x86 {

template <typename PtrType>
struct IDTDescr {};

template <>
struct IDTDescr<uint32_t> {
    uint16_t offset_1; // offset bits 0..15
    uint16_t selector; // a code segment selector in GDT or LDT
    uint8_t zero;      // unused, set to 0
    uint8_t type_attr; // type and attributes
    uint16_t offset_2; // offset bits 16..31
};

template <>
struct IDTDescr<uint64_t> {
    uint16_t offset_1; // offset bits 0..15
    uint16_t selector; // a code segment selector in GDT or LDT
    uint8_t ist;       // bits 0..2 holds Interrupt Stack Table offset, rest of bits zero.
    uint8_t type_attr; // type and attributes
    uint16_t offset_2; // offset bits 16..31
    uint32_t offset_3; // offset bits 32..63
    uint32_t zero;     // reserved
};

template <typename PtrType>
class IdtEntryImpl final : public IdtEntry {
  public:
    GuestVirtualAddress entry_point() const override { return entry_point_; }
    bool present() const override { return type_attr_ & 0x80; }
    uint8_t dpl() const override { return (type_attr_ & 0x60) >> 4; }
    bool storage_segment() const override { return type_attr_ & 0x10; }
    IdtEntryType type() const override { return static_cast<IdtEntryType>(type_attr_ & 0xF); }
    uint16_t selector() const override { return selector_; }

    IdtEntryImpl(const GuestVirtualAddress& entry_point, uint16_t selector, uint16_t type_attr)
        : entry_point_(entry_point), selector_(selector), type_attr_(type_attr) {}

  private:
    GuestVirtualAddress entry_point_;
    uint16_t selector_;
    uint8_t type_attr_;
};

template <typename PtrType>
class IdtImpl final : public Idt {
  public:
    std::unique_ptr<const IdtEntry> entry(uint index) const override {
        // Make sure the index is okay
        auto& registers = vcpu_.registers();

        if (unlikely(index > count())) {
            // TODO: Throw an exception
            return std::make_unique<IdtEntryImpl<PtrType>>(NullGuestAddress(), 0, 0);
        }

        GuestVirtualAddress pEntry(vcpu_, registers.idtr_base() + (sizeof(IDTDescr) * index));
        guest_ptr<IDTDescr> entry(pEntry);

        PtrType entry_address_ = static_cast<PtrType>(entry->offset_2) << 16 | entry->offset_1;

        if constexpr (std::is_same_v<PtrType, uint64_t>) {
            entry_address_ |= (static_cast<PtrType>(entry->offset_3) << 32);
        }

        return std::make_unique<const IdtEntryImpl<PtrType>>(
            GuestVirtualAddress(vcpu_, entry_address_), entry->selector, entry->type_attr);
    }

    uint count() const override {
        auto& registers = vcpu_.registers();
        return registers.idtr_limit() / sizeof(IDTDescr);
    };

    IdtImpl(const Vcpu& vcpu) : vcpu_(vcpu) {}

  private:
    using IDTDescr = struct IDTDescr<PtrType>;
    const Vcpu& vcpu_;
};

} // namespace x86
} // namespace introvirt