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

#include "NTSTATUS_CODE.hh"

#include <introvirt/util/json/json.hh>

#include <cstdint>
#include <memory>
#include <string>

namespace introvirt {
namespace windows {
namespace nt {

/**
 * @brief Status codes returned by Windows NT system calls.
 *
 */
class NTSTATUS final {
  public:
    /**
     * @returns True if the given status code is considered a success
     */
    static bool NT_SUCCESS(NTSTATUS_CODE code);
    /**
     * Information is a special type of NT_SUCCESS. A result can be both.
     *
     * @returns True if the given status code is considered informational.
     */
    static bool NT_INFORMATION(NTSTATUS_CODE code);
    /**
     * @returns True if the given status code is a warning
     */
    static bool NT_WARNING(NTSTATUS_CODE code);
    /**
     * @returns True if the given status code is an error
     */
    static bool NT_ERROR(NTSTATUS_CODE code);

  public:
    /**
     * @returns True if this status is a success
     */
    bool NT_SUCCESS() const;
    /**
     * NT_INFORMATION also implies NT_SUCCESS
     *
     * @returns True if this status is informational
     */
    bool NT_INFORMATION() const;
    /**
     * @returns True if this status is considered a warning
     */
    bool NT_WARNING() const;
    /**
     * @returns True if this status is considered a error
     */
    bool NT_ERROR() const;

    /**
     * @returns True if this status has been set to a value other than
     * STATUS_WINTROVIRT_UNINITIALIZED
     */
    bool initialized() const;

  public:
    /**
     * @returns The integer value of the status
     */
    uint32_t value() const;

    explicit operator uint32_t() const;

    Json::Value json() const;

    operator Json::Value() const;

    explicit operator bool() const;

    /**
     * @returns The NTSTATUS_CODE value of this code
     */
    NTSTATUS_CODE code() const;
    operator NTSTATUS_CODE() const;

  public:
    /**
     * Create an uninitialized NTSTATUS
     */
    NTSTATUS();

    /**
     * Create an NTSTATUS from a raw value
     */
    NTSTATUS(uint32_t value);

    /**
     * Create an NTSTATUS with the given value
     *
     * @param code The NTSTATUS code to use
     */
    NTSTATUS(NTSTATUS_CODE code);

    /**
     * Copy constructor. Create an NTSTATUS from the given value.
     *
     * @param other The NTSTATUS code to use
     */
    NTSTATUS(const NTSTATUS& other);

    /**
     * Assignment operator
     *
     * @param other The other NTSTATUS to copy
     * @returns The copy result
     */
    NTSTATUS& operator=(const NTSTATUS& other);

    /**
     * Move constructor
     *
     * @param other The temporary to move from
     */
    NTSTATUS(NTSTATUS&& other);

    /**
     * Move assignment operator
     *
     * @param other The other NTSTATUS to move from
     * @returns The move result
     */
    NTSTATUS& operator=(NTSTATUS&& other);

    ~NTSTATUS();

  private:
    NTSTATUS_CODE code_;
};

const std::string& to_string(NTSTATUS status);
std::ostream& operator<<(std::ostream& os, NTSTATUS status);

} /* namespace nt */
} /* namespace windows */
} /* namespace introvirt */
