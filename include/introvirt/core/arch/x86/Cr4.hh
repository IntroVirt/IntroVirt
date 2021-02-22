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
 * @brief The x86 Control Register 4
 */
class Cr4 {
  public:
    /**
     * @brief Get the VME (Virtual 8086 Mode Extensions) bit
     *
     * @return true if the VME bit is set
     * @return false if the VME bit is not set
     */
    bool vme() const;

    /**
     * @brief Get the PVI (Protected-mode Virtual Interrupts) bit
     *
     * @return true if the PVI bit is set
     * @return false if the PVI bit is not set
     */
    bool pvi() const;

    /**
     * @brief Get the TSD (Time Stamp Disable) bit
     *
     * @return true if the TSD bit is set
     * @return false if the TSD bit is not set
     */
    bool tsd() const;

    /**
     * @brief Get the DE (Debugging Extensions) bit
     *
     * @return true if the DE bit is set
     * @return false if the DE bit is not set
     */
    bool de() const;

    /**
     * @brief Get the PSE (Page Size Extension) bit
     *
     * @return true if the PSE bit is set
     * @return false if the PSE bit is not set
     */
    bool pse() const;

    /**
     * @brief Get the PAE (Physical Address Extension) bit
     *
     * @return true if the PAE bit is set
     * @return false if the PAE bit is not set
     */
    bool pae() const;

    /**
     * @brief Get the MCE (Machine Check Exception) bit
     *
     * @return true if the MCE bit is set
     * @return false if the MCE bit is not set
     */
    bool mce() const;

    /**
     * @brief Get the PGE (Page Global Enabled) bit
     *
     * @return true if the PGE bit is set
     * @return false if the PGE bit is not set
     */
    bool pge() const;

    /**
     * @brief Get the PCE (Performance-Monitoring Counter enable) bit
     *
     * @return true if the PCE bit is set
     * @return false if the PCE bit is not set
     */
    bool pce() const;

    /**
     * @brief Get the OSFXSR (Operating system support for FXSAVE and FXRSTOR instructions) bit
     *
     * @return true if the OSFXSR bit is set
     * @return false if the OSFXSR bit is not set
     */
    bool osfxsr() const;

    /**
     * @brief Get the OSXMMEXCPT bit
     *
     * @return true if the OSXMMEXCPT bit is set
     * @return false if the OSXMMEXCPT bit is not set
     */
    bool osxmmexcpt() const;

    /**
     * @brief Get the UMIP (User-Mode Instruction Prevention) bit
     *
     * @return true if the UMIP bit is set
     * @return false if the UMIP bit is not set
     */
    bool umip() const;

    /**
     * @brief Get the LA57 bit
     *
     * @return true if the LA57 bit is set
     * @return false if the LA57 bit is not set
     */
    bool la57() const;

    /**
     * @brief Get the VMXE (Virtual Machine Extensions Enable) bit
     *
     * @return true if the VMXE bit is set
     * @return false if the VMXE bit is not set
     */
    bool vmxe() const;

    /**
     * @brief Get the SMXE (Safer Mode Extensions Enable) bit
     *
     * @return true if the SMXE bit is set
     * @return false if the SMXE bit is not set
     */
    bool smxe() const;

    /**
     * @brief Get the FSGSBASE bit
     *
     * @return true if the FSGSBASE bit is set
     * @return false if the FSGSBASE bit is not set
     */
    bool fsgsbase() const;

    /**
     * @brief Get the PCIDE (PCID Enable) bit
     *
     * @return true if the PCIDE bit is set
     * @return false if the PCIDE bit is not set
     */
    bool pcide() const;

    /**
     * @brief Get the OSXSAVE (XSAVE and Processor Extended States Enable) bit
     *
     * @return true if the OSXSAVE bit is set
     * @return false if the OSXSAVE bit is not set
     */
    bool osxsave() const;

    /**
     * @brief Get the SMEP (Supervisor Mode Execution Protection Enable) bit
     *
     * @return true if the SMEP bit is set
     * @return false if the SMEP bit is not set
     */
    bool smep() const;

    /**
     * @brief Get the SMAP (Supervisor Mode Access Prevention Enable) bit
     *
     * @return true if the SMAP bit is set
     * @return false if the SMAP bit is not set
     */
    bool smap() const;

    /**
     * @brief Get the PKE (Protection Key Enable) bit
     *
     * @return true if the PKE bit is set
     * @return false if the PKE bit is not set
     */
    bool pke() const;

    /**
     * @brief Get the raw value
     *
     * @return The raw value of the register
     */
    uint64_t value() const;

    /**
     * @brief Construct a new Cr4 object
     *
     * @param cr4 The raw cr4 value
     */
    explicit Cr4(uint64_t cr4);

  private:
    const uint64_t cr4_;
};

} // namespace x86
} // namespace introvirt