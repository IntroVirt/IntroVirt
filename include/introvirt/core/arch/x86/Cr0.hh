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
 * @brief The x86 Control Register 0
 */
class Cr0 {
  public:
    /**
     * @brief Get the PE (Protected-Mode Enable) bit
     *
     * @return true if the PE bit is set
     * @return false if the PE bit is not set
     */
    bool pe() const;

    /**
     * @brief Get the MP (Monitor co-processor) bit
     *
     * @return true if the MP bit is set
     * @return false if the MP bit is not set
     */
    bool mp() const;

    /**
     * @brief Get the EM (Emulation) bit
     *
     * @return true if the EM bit is set
     * @return false if the EM bit is not set
     */
    bool em() const;

    /**
     * @brief Get the TS (Task switched) bit
     *
     * @return true if the TS bit is set
     * @return false if the TS bit is not set
     */
    bool ts() const;

    /**
     * @brief Get the ET (Extension type) bit
     *
     * @return true if the ET bit is set
     * @return false if the ET bit is not set
     */
    bool et() const;

    /**
     * @brief Get the NE (Numeric error) bit
     *
     * @return true if the NE bit is set
     * @return false if the NE bit is not set
     */
    bool ne() const;

    /**
     * @brief Get the WP (Write protect) bit
     *
     * @return true if the WP bit is set
     * @return false if the WP bit is not set
     */
    bool wp() const;

    /**
     * @brief Get the AM (Alignment mask) bit
     *
     * @return true if the AM bit is set
     * @return false if the AM bit is not set
     */
    bool am() const;

    /**
     * @brief Get the NW (Not-write through) bit
     *
     * @return true if the NW bit is set
     * @return false if the NW bit is not set
     */
    bool nw() const;

    /**
     * @brief Get the CD (Cache disable) bit
     *
     * @return true if the CD bit is set
     * @return false if the CD bit is not set
     */
    bool cd() const;

    /**
     * @brief Get the PG (Paging) bit
     *
     * @return true if the PG bit is set
     * @return false if the PG bit is not set
     */
    bool pg() const;

    /**
     * @brief Get the raw value
     *
     * @return The raw value of the register
     */
    uint64_t value() const;

    /**
     * @brief Construct a new Cr0 object
     *
     * @param cr0 The raw cr0 value
     */
    explicit Cr0(uint64_t cr0);

  private:
    const uint64_t cr0_;
};

} // namespace x86
} // namespace introvirt