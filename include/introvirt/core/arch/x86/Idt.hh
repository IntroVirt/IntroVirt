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

#include <introvirt/core/fwd.hh>
#include <introvirt/core/memory/GuestVirtualAddress.hh>

#include <cstdint>
#include <memory>
#include <vector>

namespace introvirt {
namespace x86 {

enum IdtEntryType {
    TASK_GATE_32 = 0x5,
    INTERRUPT_GATE_16 = 0x6,
    TRAP_GATE_16 = 0x7,
    INTERRUPT_GATE_32 = 0xE,
    TRAP_GATE_32 = 0xF
};

class IdtEntry {
  public:
    virtual GuestVirtualAddress entry_point() const = 0;
    virtual bool present() const = 0;
    virtual uint8_t dpl() const = 0;
    virtual bool storage_segment() const = 0;
    virtual IdtEntryType type() const = 0;
    virtual uint16_t selector() const = 0;

    virtual ~IdtEntry() = default;
};

/**
 * @brief Parser for the x86 interrupt descriptor table
 *
 */
class Idt {
  public:
    /**
     * @brief Get an IDT entry
     *
     * @param index The index into the Idt
     * @return The IdtEntry at the specified index
     */
    virtual std::unique_ptr<const IdtEntry> entry(uint index) const = 0;

    /**
     * @brief Get the number of entries in the IDT
     *
     * @return The number of entries in the IDT
     */
    virtual uint count() const = 0;

    virtual ~Idt() = default;
};

} // namespace x86
} // namespace introvirt