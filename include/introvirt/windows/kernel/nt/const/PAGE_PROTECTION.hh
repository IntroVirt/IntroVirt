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
#include <memory>
#include <string>

namespace introvirt {
namespace windows {
namespace nt {

/* TODO(papes): Clean up the PAGE_PROTECTION class */

class PAGE_PROTECTION final {
  public:
    enum PageProtectionFlag {
        UNKNOWN = 0x00,
        PAGE_NOACCESS = 0x01,
        PAGE_READONLY = 0x02,
        PAGE_READWRITE = 0x04,
        PAGE_WRITECOPY = 0x08,
        PAGE_EXECUTE = 0x10,
        PAGE_EXECUTE_READ = 0x20,
        PAGE_EXECUTE_READWRITE = 0x40,
        PAGE_EXECUTE_WRITECOPY = 0x80,
        PAGE_GUARD = 0x100,
        PAGE_NOCACHE = 0x200,
        PAGE_WRITECOMBINE = 0x400
    };

    /**
     * Create a PAGE_PROTECTION from a VAD protection
     *
     * @param protection The VAD protection to use
     * @returns A PAGE_PROTECTION object
     */
    static PAGE_PROTECTION fromVadProtection(uint32_t protection);

    /**
     * Comparison operator
     *
     * @param other The PAGE_PROTECTION to compare against
     * @returns True if the PAGE_PROTECTION values are equal
     */
    bool operator==(const PAGE_PROTECTION& other) const;

    /**
     * Assignment operator
     *
     * @other PAGE_PROECTION to copy
     */
    PAGE_PROTECTION& operator=(const PAGE_PROTECTION& other);

    /**
     * @returns True if the executable flag is set
     */
    bool isExecutable() const;

    /**
     * @returns True if the writable flag is set
     */
    bool isWritable() const;

    /**
     * @returns True if the readable flag is set
     */
    bool isReadable() const;

    /**
     * @returns True if the copy-on-write flag is set
     */
    bool isCopyOnWrite() const;

    /**
     * @returns True if readable, writable, and executable
     */
    bool isRWX() const;

    /**
     * Clear the executable bit
     */
    void clearExecutable();

    /**
     * Clear the writable bit
     */
    void clearWritable();

    /**
     * Set the copy on write bit
     */
    void changeToCopyOnWrite();

    /**
     * @returns The raw value
     */
    uint32_t value() const;

    operator uint32_t() const;

    /**
     * @returns A string representation of the protection bits
     */
    std::string string() const;

    /**
     * Create a PAGE_PROTECTION parser using a raw value
     *
     * @param protection The raw value to use
     */
    PAGE_PROTECTION(uint32_t protection = 0);

    /**
     * Create a PAGE_PROTECTION parser using a specific flag
     *
     * @param flag The flag to use
     */
    PAGE_PROTECTION(PageProtectionFlag flag);

    /**
     * Copy constructor
     *
     * @param other The PAGE_PROTECTION to copy
     */
    PAGE_PROTECTION(const PAGE_PROTECTION& other);

    ~PAGE_PROTECTION();

  private:
    uint32_t protection_;
};

std::string to_string(PAGE_PROTECTION prot);

std::ostream& operator<<(std::ostream&, PAGE_PROTECTION prot);

} // namespace nt
} // namespace windows
} // namespace introvirt
