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

#include <introvirt/core/memory/GuestVirtualAddress.hh>
#include <introvirt/core/memory/guest_ptr.hh>
#include <introvirt/windows/kernel/nt/types/LUID.hh>

namespace introvirt {
namespace windows {
namespace nt {

namespace structs {

struct _LUID {
    union {
        struct {
            uint32_t LowPart;
            int32_t HighPart;
        };
        int64_t Value;
    };
};

static_assert(sizeof(_LUID) == 0x8);

} // namespace structs

class LUID_IMPL final : public LUID {
  public:
    uint64_t value() const override;
    void value(uint64_t value) override;

    uint32_t LowPart() const override;
    void LowPart(uint32_t lowPart) override;

    int32_t HighPart() const override;
    void HighPart(int32_t highPart) override;

    LUID_IMPL(const GuestVirtualAddress& address);

  private:
    guest_ptr<structs::_LUID> luid_;
};

} // namespace nt
} // namespace windows
} // namespace introvirt