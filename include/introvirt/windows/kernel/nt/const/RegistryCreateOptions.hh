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

#include <introvirt/util/json/json.hh>

#include <cstdint>
#include <string>

namespace introvirt {
namespace windows {
namespace nt {

class RegistryCreateOptions {
  public:
    RegistryCreateOptions();
    RegistryCreateOptions(uint32_t value);

  public:
    enum Flag {
        // NOTE: These first two are only used in CreateOptions, not OpenOptions
        REG_OPTION_NON_VOLATILE = 0x00000000,
        REG_OPTION_VOLATILE = 0x00000001,
        REG_OPTION_CREATE_LINK = 0x00000002,
        REG_OPTION_BACKUP_RESTORE = 0x00000004,
    };

  public:
    /**
     * @returns The raw value
     */
    uint32_t getValue() const;

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

    operator uint32_t() const;
    operator Json::Value() const;

  private:
    uint32_t value{0};
};

/*
 * NtOpenKeyEx uses OpenOptions, which are actually the same bits
 */
using RegistryOpenOptions = RegistryCreateOptions;

std::string to_string(const RegistryCreateOptions& options, const std::string& separator = " ");

std::ostream& operator<<(std::ostream& os, const RegistryCreateOptions& options);

} /* namespace nt */
} /* namespace windows */
} /* namespace introvirt */
