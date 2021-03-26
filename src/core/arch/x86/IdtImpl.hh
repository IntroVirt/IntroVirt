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
#include <introvirt/util/compiler.hh>

#include <cassert>

namespace introvirt {
namespace x86 {

namespace structs {

template <typename PtrType>
struct _IDTDescr {};

template <>
struct _IDTDescr<uint32_t> {
    uint16_t offset_1; // offset bits 0..15
    uint16_t selector; // a code segment selector in GDT or LDT
    uint8_t zero;      // unused, set to 0
    uint8_t type_attr; // type and attributes
    uint16_t offset_2; // offset bits 16..31
};

template <>
struct _IDTDescr<uint64_t> {
    uint16_t offset_1; // offset bits 0..15
    uint16_t selector; // a code segment selector in GDT or LDT
    uint8_t ist;       // bits 0..2 holds Interrupt Stack Table offset, rest of bits zero.
    uint8_t type_attr; // type and attributes
    uint16_t offset_2; // offset bits 16..31
    uint32_t offset_3; // offset bits 32..63
    uint32_t zero;     // reserved
};

} // namespace structs

template <typename PtrType>
class IdtEntryImpl final : public IdtEntry {
    using _IDTDescr = structs::_IDTDescr<PtrType>;

  public:
    guest_ptr<void> entry_point() const override {
        PtrType entry_address = static_cast<PtrType>(ptr_->offset_2) << 16 | ptr_->offset_1;
        if constexpr (std::is_same_v<PtrType, uint64_t>) {
            entry_address |= (static_cast<PtrType>(ptr_->offset_3) << 32);
        }
        // Copy the original pointer as context and update it's address
        guest_ptr<void> result = ptr_;
        result.reset(entry_address);
        return result;
    }
    bool present() const override { return ptr_->type_attr & 0x80; }
    uint8_t dpl() const override { return (ptr_->type_attr & 0x60) >> 4; }
    bool storage_segment() const override { return ptr_->type_attr & 0x10; }
    IdtEntryType type() const override { return static_cast<IdtEntryType>(ptr_->type_attr & 0xF); }
    uint16_t selector() const override { return ptr_->selector; }

    IdtEntryImpl(guest_ptr<_IDTDescr>&& ptr) : ptr_(ptr) {}

  private:
    guest_ptr<_IDTDescr> ptr_;
};

template <typename PtrType>
class IdtImpl final : public Idt {
    using _IDTDescr = structs::_IDTDescr<PtrType>;
    using _IdtEntryImpl = IdtEntryImpl<PtrType>;

  public:
    std::unique_ptr<const IdtEntry> entry(size_t index) const override {
        // Crash if index is out of bounds
        introvirt_assert(index < count(), "");

        // Calculate the address of the entry
        auto& regs = vcpu_.registers();
        guest_ptr<_IDTDescr> pEntry(vcpu_, regs.idtr_base() + (sizeof(_IDTDescr) * index));

        // Create the instance
        return std::make_unique<const _IdtEntryImpl>(std::move(pEntry));
    }

    uint count() const override {
        auto& registers = vcpu_.registers();
        return registers.idtr_limit() / sizeof(_IDTDescr);
    };

    IdtImpl(const Vcpu& vcpu) : vcpu_(vcpu) {}

  private:
    const Vcpu& vcpu_;
};

} // namespace x86
} // namespace introvirt