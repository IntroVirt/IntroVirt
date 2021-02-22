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
#include <introvirt/windows/libraries/ws2_32/types/WSADATA.hh>

namespace introvirt {
namespace windows {
namespace ws2_32 {

namespace structs {

template <typename PtrType>
struct _WSADATA {
    uint16_t wVersion;
    uint16_t wHighVersion;
};

}; // namespace structs

/*
 * TODO: This class varies based on the version.
 * We'll have to abstract all of that away in here.
 */
template <typename PtrType>
class WSADATA_IMPL final : public WSADATA {
  public:
    uint16_t wVersion() const override { return data_->wVersion; }
    void wVersion(uint16_t wVersion) override { data_->wVersion = wVersion; }

    uint16_t wHighVersion() const override { return data_->wHighVersion; }
    void wHighVersion(uint16_t wHighVersion) override { data_->wHighVersion = wHighVersion; }

    WSADATA_IMPL(const GuestVirtualAddress& gva) : gva_(gva), data_(gva) {}

  private:
    GuestVirtualAddress gva_;
    guest_ptr<structs::_WSADATA<PtrType>> data_;
};

} // namespace ws2_32
} // namespace windows
} // namespace introvirt