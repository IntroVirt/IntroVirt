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

/**
 * @brief Windows memory allocation types
 *
 * See the Microsoft page for <a
 * href="https://docs.microsoft.com/en-us/windows/win32/api/memoryapi/nf-memoryapi-virtualalloc">VirtualAlloc</a>
 *
 */
enum MEMORY_ALLOCATION_TYPE_FLAGS {
    MEM_COMMIT = 0x00001000,
    MEM_RESERVE = 0x00002000,
    MEM_DECOMMIT = 0x00004000,
    MEM_RELEASE = 0x00008000,
    MEM_FREE = 0x00010000,
    MEM_PRIVATE = 0x00020000,
    MEM_MAPPED = 0x00040000,
    MEM_RESET = 0x00080000,
    MEM_TOP_DOWN = 0x00100000,
    MEM_PHYSICAL = 0x00400000,
    MEM_IMAGE = 0x1000000,
    MEM_LARGE_PAGES = 0x20000000,
    MEM_4MB_PAGES = 0x80000000
};

/**
 * @brief Class for MEMORY_ALLOCATION_TYPE flags
 *
 */
class MEMORY_ALLOCATION_TYPE final {
  public:
    bool MEM_COMMIT() const;
    bool MEM_RESERVE() const;
    bool MEM_DECOMMIT() const;
    bool MEM_RELEASE() const;
    bool MEM_FREE() const;
    bool MEM_PRIVATE() const;
    bool MEM_MAPPED() const;
    bool MEM_RESET() const;
    bool MEM_TOP_DOWN() const;
    bool MEM_PHYSICAL() const;
    bool MEM_IMAGE() const;
    bool MEM_LARGE_PAGES() const;
    bool MEM_4MB_PAGES() const;

    void MEM_COMMIT(bool enabled);
    void MEM_RESERVE(bool enabled);
    void MEM_DECOMMIT(bool enabled);
    void MEM_RELEASE(bool enabled);
    void MEM_FREE(bool enabled);
    void MEM_PRIVATE(bool enabled);
    void MEM_MAPPED(bool enabled);
    void MEM_RESET(bool enabled);
    void MEM_TOP_DOWN(bool enabled);
    void MEM_PHYSICAL(bool enabled);
    void MEM_IMAGE(bool enabled);
    void MEM_LARGE_PAGES(bool enabled);
    void MEM_4MB_PAGES(bool enabled);

    std::string string() const;
    operator Json::Value() const;
    uint32_t value() const { return value_; }
    operator uint32_t() const { return value_; }
    bool operator==(const MEMORY_ALLOCATION_TYPE& other) const;
    MEMORY_ALLOCATION_TYPE(uint32_t value = 0) : value_(value) {}
    void stream(std::ostream&) const;

  private:
    uint32_t value_;
};

std::ostream& operator<<(std::ostream& os, const MEMORY_ALLOCATION_TYPE& allocationType);
std::string to_string(const MEMORY_ALLOCATION_TYPE& allocationType);

} // namespace nt
} // namespace windows
} // namespace introvirt
