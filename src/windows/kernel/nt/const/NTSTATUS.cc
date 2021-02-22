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

#include "NTSTATUS_ascii.hh"

#include <introvirt/util/compiler.hh>
#include <introvirt/windows/kernel/nt/const/NTSTATUS.hh>

using namespace std;

namespace introvirt {
namespace windows {
namespace nt {

uint32_t NTSTATUS::value() const { return code_; }

NTSTATUS::operator uint32_t() const { return code_; }

NTSTATUS::operator bool() const { return code_ != NTSTATUS_CODE::STATUS_WINTROVIRT_UNINITIALIZED; }

Json::Value NTSTATUS::json() const {
    Json::Value result;

    result["value"] = value();
    result["string"] = string();

    return result;
}

NTSTATUS::operator Json::Value() const { return json(); }

NTSTATUS_CODE NTSTATUS::code() const { return code_; }
NTSTATUS::operator NTSTATUS_CODE() const { return code_; }

// Blank constructor
NTSTATUS::NTSTATUS() : NTSTATUS(STATUS_WINTROVIRT_UNINITIALIZED) {}

NTSTATUS::NTSTATUS(uint32_t value) : code_(static_cast<NTSTATUS_CODE>(value)) {}

// Normal constructor
NTSTATUS::NTSTATUS(NTSTATUS_CODE code) : code_(code) {}

// Copy constructor
NTSTATUS::NTSTATUS(const NTSTATUS& other) = default;

// Copy assignment operator
NTSTATUS& NTSTATUS::operator=(const NTSTATUS& other) = default;

bool NTSTATUS::NT_SUCCESS(NTSTATUS_CODE code) { return (code <= 0x7FFFFFFF); }
bool NTSTATUS::NT_INFORMATION(NTSTATUS_CODE code) {
    return NT_SUCCESS(code) && (code >= 0x40000000);
}
bool NTSTATUS::NT_WARNING(NTSTATUS_CODE code) {
    return (code >= 0x80000000) && (code <= 0xBFFFFFFF);
}
bool NTSTATUS::NT_ERROR(NTSTATUS_CODE code) { return (code >= 0xC0000000) && (code <= 0xFFFFFFFF); }
bool NTSTATUS::NT_SUCCESS() const { return NT_SUCCESS(code()); }
bool NTSTATUS::NT_INFORMATION() const { return NT_INFORMATION(code()); }
bool NTSTATUS::NT_WARNING() const { return NT_WARNING(code()); }
bool NTSTATUS::NT_ERROR() const { return NT_ERROR(code()); }
bool NTSTATUS::initialized() const { return code() != STATUS_WINTROVIRT_UNINITIALIZED; }

const std::string& to_string(NTSTATUS_CODE code) {
    auto iter = CodeToAscii.find(code);
    if (unlikely(iter == CodeToAscii.end())) {
        iter = CodeToAscii.find(STATUS_WINTROVIRT_UNKNOWN_CODE);
    }
    return iter->second;
}

std::ostream& operator<<(std::ostream& os, NTSTATUS_CODE code) {
    os << to_string(code);
    return os;
}

const std::string& to_string(NTSTATUS status) { return to_string(status.code()); }

std::ostream& operator<<(std::ostream& os, NTSTATUS status) {
    os << to_string(status);
    return os;
}

NTSTATUS::NTSTATUS(NTSTATUS&& other) = default;
NTSTATUS& NTSTATUS::operator=(NTSTATUS&& other) = default;
NTSTATUS::~NTSTATUS() = default;

} // namespace nt
} // namespace windows
} // namespace introvirt
