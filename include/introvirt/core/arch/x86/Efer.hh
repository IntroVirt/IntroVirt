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

#include <introvirt/util/compiler.hh>

#include <cstdint>

namespace introvirt {
namespace x86 {

/**
 * @brief The x86 Extended Feature Enable Register
 */
class Efer {
  public:
    /**
     * @brief Get the SCE (System Call Extensions) bit
     *
     * @return true if the SCE bit is set
     * @return false if the SCE bit is not set
     */
    bool sce() const;

    /**
     * @brief Get the LME (Long Mode Enable) bit
     *
     * @return true if the LME bit is set
     * @return false if the LME bit is not set
     */
    bool lme() const;

    /**
     * @brief Get the LMA (Long Mode Active) bit
     *
     * @return true if the LMA bit is set
     * @return false if the LMA bit is not set
     */
    bool lma() const;

    /**
     * @brief Get the NXE (No-Execute Enable) bit
     *
     * @return true if the NXE bit is set
     * @return false if the NXE bit is not set
     */
    bool nxe() const;

    /**
     * @brief Get the SVME (Secure Virtual Machine Enable) bit
     *
     * @return true if the SVME bit is set
     * @return false if the SVME bit is not set
     */
    bool svme() const;

    /**
     * @brief Get the LMSLE (Long Mode Segment Limit Enable) bit
     *
     * @return true if the LMSLE bit is set
     * @return false if the LMSLE bit is not set
     */
    bool lmsle() const;

    /**
     * @brief Get the FFXSR (Fast FXSAVE/FXRSTOR) bit
     *
     * @return true if the FFXSR bit is set
     * @return false if the FFXSR bit is not set
     */
    bool ffxsr() const;

    /**
     * @brief Get the TCE (Translation Cache Extension) bit
     *
     * @return true if the TCE bit is set
     * @return false if the TCE bit is not set
     */
    bool tce() const;

    /**
     * @brief Get the raw value of the EFER MSR
     *
     * @return uint64_t The raw value
     */
    uint64_t value() const;

    /**
     * @brief Construct a new Efer object
     *
     * @param efer The efer value to use
     */
    explicit Efer(uint64_t efer) HOT : efer_(efer){};

    ~Efer() = default;

  private:
    const uint64_t efer_;
};

} // namespace x86
} // namespace introvirt