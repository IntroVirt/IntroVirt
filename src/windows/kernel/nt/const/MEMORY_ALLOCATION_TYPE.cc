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

#include <introvirt/windows/kernel/nt/const/MEMORY_ALLOCATION_TYPE.hh>
#include <sstream>

namespace introvirt {
namespace windows {
namespace nt {

bool MEMORY_ALLOCATION_TYPE::MEM_COMMIT() const {
    return value_ & MEMORY_ALLOCATION_TYPE_FLAGS::MEM_COMMIT;
}
bool MEMORY_ALLOCATION_TYPE::MEM_RESERVE() const {
    return value_ & MEMORY_ALLOCATION_TYPE_FLAGS::MEM_RESERVE;
}
bool MEMORY_ALLOCATION_TYPE::MEM_DECOMMIT() const {
    return value_ & MEMORY_ALLOCATION_TYPE_FLAGS::MEM_DECOMMIT;
}
bool MEMORY_ALLOCATION_TYPE::MEM_RELEASE() const {
    return value_ & MEMORY_ALLOCATION_TYPE_FLAGS::MEM_RELEASE;
}
bool MEMORY_ALLOCATION_TYPE::MEM_FREE() const {
    return value_ & MEMORY_ALLOCATION_TYPE_FLAGS::MEM_FREE;
}
bool MEMORY_ALLOCATION_TYPE::MEM_PRIVATE() const {
    return value_ & MEMORY_ALLOCATION_TYPE_FLAGS::MEM_PRIVATE;
}
bool MEMORY_ALLOCATION_TYPE::MEM_MAPPED() const {
    return value_ & MEMORY_ALLOCATION_TYPE_FLAGS::MEM_MAPPED;
}
bool MEMORY_ALLOCATION_TYPE::MEM_RESET() const {
    return value_ & MEMORY_ALLOCATION_TYPE_FLAGS::MEM_RESET;
}
bool MEMORY_ALLOCATION_TYPE::MEM_TOP_DOWN() const {
    return value_ & MEMORY_ALLOCATION_TYPE_FLAGS::MEM_TOP_DOWN;
}
bool MEMORY_ALLOCATION_TYPE::MEM_PHYSICAL() const {
    return value_ & MEMORY_ALLOCATION_TYPE_FLAGS::MEM_PHYSICAL;
}
bool MEMORY_ALLOCATION_TYPE::MEM_IMAGE() const {
    return value_ & MEMORY_ALLOCATION_TYPE_FLAGS::MEM_IMAGE;
}
bool MEMORY_ALLOCATION_TYPE::MEM_LARGE_PAGES() const {
    return value_ & MEMORY_ALLOCATION_TYPE_FLAGS::MEM_LARGE_PAGES;
}
bool MEMORY_ALLOCATION_TYPE::MEM_4MB_PAGES() const {
    return value_ & MEMORY_ALLOCATION_TYPE_FLAGS::MEM_4MB_PAGES;
}

inline static void set_bit(MEMORY_ALLOCATION_TYPE_FLAGS bit, uint32_t& value, bool enabled) {
    if (enabled)
        value |= bit;
    else
        value &= ~bit;
}

void MEMORY_ALLOCATION_TYPE::MEM_COMMIT(bool enabled) {
    set_bit(MEMORY_ALLOCATION_TYPE_FLAGS::MEM_COMMIT, value_, enabled);
}
void MEMORY_ALLOCATION_TYPE::MEM_RESERVE(bool enabled) {
    set_bit(MEMORY_ALLOCATION_TYPE_FLAGS::MEM_RESERVE, value_, enabled);
}
void MEMORY_ALLOCATION_TYPE::MEM_DECOMMIT(bool enabled) {
    set_bit(MEMORY_ALLOCATION_TYPE_FLAGS::MEM_DECOMMIT, value_, enabled);
}
void MEMORY_ALLOCATION_TYPE::MEM_RELEASE(bool enabled) {
    set_bit(MEMORY_ALLOCATION_TYPE_FLAGS::MEM_RELEASE, value_, enabled);
}
void MEMORY_ALLOCATION_TYPE::MEM_FREE(bool enabled) {
    set_bit(MEMORY_ALLOCATION_TYPE_FLAGS::MEM_FREE, value_, enabled);
}
void MEMORY_ALLOCATION_TYPE::MEM_PRIVATE(bool enabled) {
    set_bit(MEMORY_ALLOCATION_TYPE_FLAGS::MEM_PRIVATE, value_, enabled);
}
void MEMORY_ALLOCATION_TYPE::MEM_MAPPED(bool enabled) {
    set_bit(MEMORY_ALLOCATION_TYPE_FLAGS::MEM_MAPPED, value_, enabled);
}
void MEMORY_ALLOCATION_TYPE::MEM_RESET(bool enabled) {
    set_bit(MEMORY_ALLOCATION_TYPE_FLAGS::MEM_RESET, value_, enabled);
}
void MEMORY_ALLOCATION_TYPE::MEM_TOP_DOWN(bool enabled) {
    set_bit(MEMORY_ALLOCATION_TYPE_FLAGS::MEM_TOP_DOWN, value_, enabled);
}
void MEMORY_ALLOCATION_TYPE::MEM_PHYSICAL(bool enabled) {
    set_bit(MEMORY_ALLOCATION_TYPE_FLAGS::MEM_PHYSICAL, value_, enabled);
}
void MEMORY_ALLOCATION_TYPE::MEM_IMAGE(bool enabled) {
    set_bit(MEMORY_ALLOCATION_TYPE_FLAGS::MEM_IMAGE, value_, enabled);
}
void MEMORY_ALLOCATION_TYPE::MEM_LARGE_PAGES(bool enabled) {
    set_bit(MEMORY_ALLOCATION_TYPE_FLAGS::MEM_LARGE_PAGES, value_, enabled);
}
void MEMORY_ALLOCATION_TYPE::MEM_4MB_PAGES(bool enabled) {
    set_bit(MEMORY_ALLOCATION_TYPE_FLAGS::MEM_4MB_PAGES, value_, enabled);
}

bool MEMORY_ALLOCATION_TYPE::operator==(const MEMORY_ALLOCATION_TYPE& other) const {
    return value_ == other.value_;
}

MEMORY_ALLOCATION_TYPE::operator Json::Value() const { return value_; }

void MEMORY_ALLOCATION_TYPE::stream(std::ostream& os) const {
    if (MEM_COMMIT())
        os << "MEM_COMMIT ";
    if (MEM_PHYSICAL())
        os << "MEM_PHYSICAL ";
    if (MEM_RESERVE())
        os << "MEM_RESERVE ";
    if (MEM_RESET())
        os << "MEM_RESET ";
    if (MEM_TOP_DOWN())
        os << "MEM_TOP_DOWN ";
    if (MEM_DECOMMIT())
        os << "MEM_DECOMMIT ";
    if (MEM_RELEASE())
        os << "MEM_RELEASE ";
    if (MEM_PRIVATE())
        os << "MEM_PRIVATE ";
    if (MEM_MAPPED())
        os << "MEM_MAPPED ";
    if (MEM_4MB_PAGES())
        os << "MEM_4MB_PAGES ";
    if (MEM_LARGE_PAGES())
        os << "MEM_LARGE_PAGES ";
    if (MEM_TOP_DOWN())
        os << "MEM_TOP_DOWN ";
    if (MEM_IMAGE())
        os << "MEM_IMAGE ";
}

std::string MEMORY_ALLOCATION_TYPE::string() const {
    std::stringstream ss;
    stream(ss);
    return ss.str();
}

std::ostream& operator<<(std::ostream& os, const MEMORY_ALLOCATION_TYPE& allocationType) {
    os << to_string(allocationType);
    return os;
}

std::string to_string(const MEMORY_ALLOCATION_TYPE& allocationType) {
    return allocationType.string();
}

} // namespace nt
} // namespace windows
} // namespace introvirt
