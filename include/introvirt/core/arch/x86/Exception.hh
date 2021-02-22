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

#include <ostream>
#include <string>

namespace introvirt {
namespace x86 {

/**
 * @brief x86 exception codes
 */
enum class Exception {
    DIVIDE_ERROR = 0,
    DEBUG = 1,
    NMI = 2,
    INT3 = 3,
    OVERFLOW = 4,
    BOUNDS = 5,
    INVALID_OP = 6,
    NO_DEVICE = 7,
    DOUBLE_FAULT = 8,
    COPRO_SEG = 9,
    INVALID_TSS = 10,
    NO_SEGMENT = 11,
    STACK_ERROR = 12,
    GP_FAULT = 13,
    PAGE_FAULT = 14,
    SPURIOUS_INT = 15,
    COPRO_ERROR = 16,
    ALIGNMENT_CHECK = 17,
    MACHINE_CHECK = 18,
    SIMD_ERROR = 19,

    UNKNOWN = -1,
};

/**
 * @brief Convert an Exception enum value to a std::string
 *
 * @param exception The exception to convert
 * @return A string value containing the Exception enum value
 */
const std::string& to_string(Exception exception);

/**
 * @brief Stream output operator for Exception
 *
 * @param os The output stream to write to
 * @param exception The exception to write
 * @return A reference to the given os
 */
std::ostream& operator<<(std::ostream& os, Exception exception);

} // namespace x86
} // namespace introvirt