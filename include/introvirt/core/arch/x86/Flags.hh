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

#include <cstdint>

namespace introvirt {
namespace x86 {

/**
 * @brief Handler for the x86 EFLAGS/RFLAGS register
 */
class Flags {
  public:
    /**
     * @brief Get the CF (Carry flag) bit
     *
     * @return true if the CF bit is set
     * @return false if the CF bit is not set
     */
    bool carry() const;

    /**
     * @brief Get the PF (Parity flag) bit
     *
     * @return true if the PF bit is set
     * @return false if the PF bit is not set
     */
    bool parity() const;

    /**
     * @brief Get the AF (Adjust flag) bit
     *
     * @return true if the AF bit is set
     * @return false if the AF bit is not set
     */
    bool adjust() const;

    /**
     * @brief Get the ZF (Zero flag) bit
     *
     * @return true if the ZF bit is set
     * @return false if the ZF bit is not set
     */
    bool zero() const;

    /**
     * @brief Get the SF (Sign flag) bit
     *
     * @return true if the SF bit is set
     * @return false if the SF bit is not set
     */
    bool sign() const;

    /**
     * @brief Get the TF (Trap flag) bit
     *
     * @return true if the TF bit is set
     * @return false if the TF bit is not set
     */
    bool trap() const;

    /**
     * @brief Get the IF (interrupt flag) bit
     *
     * @return true if the IF bit is set
     * @return false if the IF bit is not set
     */
    bool interrupt() const;

    /**
     * @brief Set the IF (interrupt flag) flag
     *
     * @param val The value to the flag to
     */
    void interrupt(bool val);

    /**
     * @brief Get the DF (Direction flag) bit
     *
     * @return true if the DF bit is set
     * @return false if the DF bit is not set
     */
    bool direction() const;

    /**
     * @brief Get the OF (Overflow flag) bit
     *
     * @return true if the OF bit is set
     * @return false if the OF bit is not set
     */
    bool overflow() const;

    /**
     * @brief Get the IOPL (I/O privilege level) bits
     *
     * @return The IOPL value
     */
    int8_t iopl() const;

    /**
     * @brief Get the NT (Nested-task flag) bit
     *
     * @return true if the NT bit is set
     * @return false if the NT bit is not set
     */
    bool nested_task() const;

    /**
     * @brief Get the RF (Resume flag) bit
     *
     * @return true if the RF bit is set
     * @return false if the RF bit is not set
     */
    bool resume() const;

    /**
     * @brief Get the VM (Virtual 8086 mode) bit
     *
     * @return true if the VM bit is set
     * @return false if the VM bit is not set
     */
    bool virtual_8086() const;

    /**
     * @brief Get the AC (Aligment-check) bit
     *
     * @return true if the AC bit is set
     * @return false if the AC bit is not set
     */
    bool alignment_check() const;

    /**
     * @brief Get the VIF (Virtual-interrupt flag) bit
     *
     * @return true if the VIF bit is set
     * @return false if the VIF bit is not set
     */
    bool virtual_interrupt() const;

    /**
     * @brief Get the VIP (Virtual-interrupt pending flag) bit
     *
     * @return true if the VIP bit is set
     * @return false if the VIP bit is not set
     */
    bool virtual_interrupt_pending() const;

    /**
     * @brief Get the ID (CPUID) bit
     *
     * @return true if the ID bit is set
     * @return false if the ID bit is not set
     */
    bool cpuid() const;

    /**
     * @brief Get the raw flags value
     *
     * @return uint64_t The raw flags value
     */
    uint64_t value() const;

    /**
     * @brief Set the raw flags value
     *
     * @param value The value to set
     */
    void value(uint64_t value);

    /**
     * @brief Construct a new Flags instances
     *
     * @param flags A reference to the flags value to use/update
     */
    explicit Flags();

    /**
     * @brief Construct a new Flags instances
     *
     * @param flags The value to initially set
     */
    explicit Flags(uint64_t flags);

    /**
     * @brief Construct a new Flags instances using a reference variable
     *
     * This is primarily intended for backends to use to update a struct of registers.
     *
     * @param flags A reference to the flags value to use/update
     * @param modified A variable to set to true if any field is modified
     */
    explicit Flags(uint64_t& flags, bool* modified);

    Flags(const Flags& src) = delete;
    Flags& operator=(const Flags&) = delete;

    Flags& operator=(Flags&&) noexcept = default;

  private:
    inline void set_modified() {
        if (modified_ != nullptr)
            *modified_ = true;
    }

    uint64_t value_ = 0; // Used only for the default constructorm
    uint64_t* flags_;
    bool* modified_ = nullptr;
};

} // namespace x86
} // namespace introvirt