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
#include <string>

namespace introvirt {
namespace windows {
namespace nt {

class MapType {
  public:
    MapType();
    MapType(uint32_t value);

  public:
    enum Flag {
        MAP_PROCESS = 0x1,
        MAP_SYSTEM = 0x2,
    };

  public:
    /**
     * @returns The raw value
     */
    uint32_t getValue() const;

    operator uint32_t() const;

    /**
     * @param value The raw value to set
     */
    void setValue(uint32_t value);

    /**
     * @param flag The flag to check
     * @returns True if the given flag is enabled
     */
    bool isFlagEnabled(Flag flag) const;

    /**
     * @param flag The flag to disable
     */
    void disableFlag(Flag flag);

    /**
     * @param flag The flag to enable
     */
    void enableFlag(Flag flag);

    /**
     * @param separator The separator to use between flags
     * @returns A human readable string
     */
    std::string to_string(const std::string& separator = " ") const;

  private:
    uint32_t value{0};
};

std::string to_string(const MapType& options, const std::string& separator = " ");

} /* namespace nt */
} /* namespace windows */
} /* namespace introvirt */
