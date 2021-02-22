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
#include <introvirt/windows/libraries/advapi32/types/BLOB.hh>

#include <cstdint>

namespace introvirt {
namespace windows {
namespace advapi32 {

struct _PLAINTEXTKEYBLOB;

class PLAINTEXTKEYBLOB final : public BLOB {
  public:
    guest_ptr<const uint8_t[]> KeyData() const;

    PLAINTEXTKEYBLOB(const GuestVirtualAddress& gva, uint32_t length);

  private:
    guest_ptr<uint8_t[]> key_data_;
};

} // namespace advapi32
} // namespace windows
} // namespace introvirt