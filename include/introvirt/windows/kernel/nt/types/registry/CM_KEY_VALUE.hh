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
#include <introvirt/windows/kernel/nt/const/REG_TYPE.hh>
#include <introvirt/windows/kernel/nt/fwd.hh>

#include <cstdint>
#include <memory>
#include <string>

namespace introvirt {
namespace windows {
namespace nt {

class HIVE;
class KEY_VALUE;

class CM_KEY_VALUE {
  public:
    virtual const std::string& Name() const = 0;
    virtual const KEY_VALUE* Data() const = 0;
    virtual REG_TYPE Type() const = 0;
    virtual GuestVirtualAddress address() const = 0;

    virtual ~CM_KEY_VALUE() = default;
};

} /* namespace nt */
} /* namespace windows */
} /* namespace introvirt */
