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
    PtrType h_name;
    PtrType h_aliases;
    uint16_t h_addrtype;
    uint16_t h_length;
    PtrType h_addr_list;
} __attribute__((packed, aligned(sizeof(PtrType))));

}; // namespace structs

/*
 * TODO: This class varies based on the version.
 * We'll have to abstract all of that away in here.
 */
template <typename PtrType>
class HOSTENT_IMPL final : public HOSTENT {
  public:
    // Direct structure members
    GuestVirtualAddress ph_name() const override { return gva_.create(data_->h_name); }
    void ph_name(const GuestVirtualAddress& gva) override { data_->h_name = gva.value(); }

    GuestVirtualAddress ph_aliases() const override { return gva_.create(data_->h_aliases); }
    void ph_aliases(const GuestVirtualAddress& gva) override { data_->h_aliases = gva.value(); }

    uint16_t h_addrtype() const override { return data_->h_addrtype; }
    void h_addrtype(uint16_t h_addrtype) override { data_->h_addrtype = h_addrtype; }

    uint16_t h_length() const override { return data_->h_length; }
    void h_length(uint16_t h_length) override { data_->h_length = h_length; }

    GuestVirtualAddress ph_addr_list() const override { return gva_.create(data_->h_addr_list); }
    void ph_addr_list(const GuestVirtualAddress& gva) override { data_->h_addr_list = gva.value(); }

    // Helpers
    std::string h_name() const override {
        GuestVirtualAddress gva = ph_name();
        if (!gva) {
            return std::string();
        }
        auto mapping = map_guest_cstr(gva);
        return std::string(mapping.get(), mapping.length());
    }

    std::vector<std::string> h_aliases() const override {
        std::vector<std::string> result;
        GuestVirtualAddress pArray = ph_aliases();

        if (pArray) {
            GuestVirtualAddress pEntry = pArray.create(*guest_ptr<PtrType>(pArray));
            while (pEntry) {
                // Read the entry
                auto mapping = map_guest_cstr(pEntry);
                result.emplace_back(mapping.get(), mapping.length());

                // Move to the next entry
                pArray += sizeof(PtrType);
                pEntry = pArray.create(*guest_ptr<PtrType>(pArray));
            }
        }
        return result;
    }

    HOSTENT_IMPL(const GuestVirtualAddress& gva) : gva_(gva), data_(gva) {}

  private:
    GuestVirtualAddress gva_;
    guest_ptr<structs::_HOSTENT<PtrType>> data_;
};

} // namespace ws2_32
} // namespace windows
} // namespace introvirt