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

#include "TOKEN_INFORMATION.hh"

#include <introvirt/windows/kernel/nt/types/SID.hh>

namespace introvirt {
namespace windows {
namespace nt {

class TOKEN_OWNER : public TOKEN_INFORMATION {
  public:
    virtual GuestVirtualAddress OwnerPtr() const = 0;
    virtual void OwnerPtr(const GuestVirtualAddress& gva) = 0;

    virtual SID* Owner() = 0;
    virtual const SID* Owner() const = 0;
};

} /* namespace nt */
} /* namespace windows */
} /* namespace introvirt */
