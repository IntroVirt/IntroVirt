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

#include <introvirt/core/memory/guest_ptr.hh>
#include <introvirt/windows/libraries/ws2_32/types/HOSTENT.hh>

namespace introvirt {
namespace windows {
namespace ws2_32 {

namespace structs {

template <typename PtrType>
struct _HOSTENT {
    guest_member_ptr<char[], PtrType> h_name;
    guest_member_ptr<char*, PtrType> h_aliases;
    uint16_t h_addrtype;
    uint16_t h_length;
    guest_member_ptr<uint8_t*, PtrType> h_addr_list;
};

static_assert(offsetof(_HOSTENT<uint32_t>, h_name) == 0);
static_assert(offsetof(_HOSTENT<uint32_t>, h_aliases) == 4);
static_assert(offsetof(_HOSTENT<uint32_t>, h_addrtype) == 8);
static_assert(offsetof(_HOSTENT<uint32_t>, h_length) == 10);
static_assert(offsetof(_HOSTENT<uint32_t>, h_addr_list) == 12);

static_assert(offsetof(_HOSTENT<uint64_t>, h_name) == 0);
static_assert(offsetof(_HOSTENT<uint64_t>, h_aliases) == 8);
static_assert(offsetof(_HOSTENT<uint64_t>, h_addrtype) == 16);
static_assert(offsetof(_HOSTENT<uint64_t>, h_length) == 18);
static_assert(offsetof(_HOSTENT<uint64_t>, h_addr_list) == 24);

}; // namespace structs

/*
 * TODO: This class varies based on the version.
 * We'll have to abstract all of that away in here.
 */
template <typename PtrType>
class HOSTENT_IMPL final : public HOSTENT {
    static inline constexpr bool x64_ = std::is_same_v<PtrType, uint64_t>;

  public:
    // Direct structure members
    guest_ptr<char[]> ph_name() const override { return ptr_->h_name.cstring(ptr_); }
    void ph_name(const guest_ptr<char[]>& ptr) override { ptr_->h_name.set(ptr); }

    guest_ptr<char*, guest_ptr_t> ph_aliases() const override {
        return guest_ptr<char*, guest_ptr_t>(ptr_->h_aliases.get(ptr_));
    }
    void ph_aliases(const guest_ptr<char*, guest_ptr_t>& ptr) override { ptr_->h_aliases.set(ptr); }

    uint16_t h_addrtype() const override { return ptr_->h_addrtype; }
    void h_addrtype(uint16_t h_addrtype) override { ptr_->h_addrtype = h_addrtype; }

    uint16_t h_length() const override { return ptr_->h_length; }
    void h_length(uint16_t h_length) override { ptr_->h_length = h_length; }

    guest_ptr<uint8_t*, guest_ptr_t> ph_addr_list() const override {
        return ptr_->h_addr_list.get(ptr_);
    }
    void ph_addr_list(const guest_ptr<uint8_t*, guest_ptr_t>& ptr) override {
        ptr_->h_addr_list.set(ptr);
    }

    std::vector<guest_ptr<char[]>> h_aliases() const override {
        std::vector<guest_ptr<char[]>> result;

        // A pointer to a null terminated array of pointers
        guest_ptr<char*, PtrType> pAliases = ptr_->h_aliases.get(ptr_);
        // Walk each entry and check for null
        for (guest_ptr<char> pAlias = pAliases.get(); pAlias; ++pAliases) {
            // Map the string at each entry and add it to the result
            result.emplace_back(map_guest_cstring(pAlias));
        }
        return result;
    }

    HOSTENT_IMPL(const guest_ptr<void>& ptr) : ptr_(ptr) {}

  private:
    guest_ptr<structs::_HOSTENT<PtrType>> ptr_;
};

} // namespace ws2_32
} // namespace windows
} // namespace introvirt