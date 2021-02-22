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

#include <introvirt/windows/pe/const/UNWIND_OP.hh>

#include <cstdint>

namespace introvirt {
namespace windows {
namespace pe {

class UnwindCode {
  public:
    virtual uint8_t CodeOffset() const = 0;
    virtual UNWIND_OP UnwindOp() const = 0;
    virtual uint8_t OpInfo() const = 0;
    virtual uint16_t FrameOffset() const = 0;
    virtual uint8_t CodeCount() const = 0;
    virtual uint32_t LargeAllocSize() const = 0;

    virtual ~UnwindCode() = default;
};

} // namespace pe
} // namespace windows
} // namespace introvirt
