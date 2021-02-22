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

#include <introvirt/core/fwd.hh>
#include <introvirt/windows/pe/fwd.hh>

#include <cstdint>
#include <memory>

namespace introvirt {
namespace windows {
namespace pe {

class RUNTIME_FUNCTION {
  public:
    virtual uint32_t BeginAddress() const = 0;
    virtual uint32_t EndAddress() const = 0;
    virtual const UnwindInfo* UnwindData() const = 0;

    virtual bool is_chained() const = 0;
    virtual const RUNTIME_FUNCTION* chained_function() const = 0;

    virtual ~RUNTIME_FUNCTION() = default;
};

} // namespace pe
} // namespace windows
} // namespace introvirt
