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

#include "RUNTIME_FUNCTION.hh"
#include "UnwindCode.hh"

#include <introvirt/windows/pe/const/UNWIND_FLAGS.hh>

#include <cstdint>
#include <memory>
#include <vector>

namespace introvirt {
namespace windows {
namespace pe {

class UnwindInfo {
  public:
    virtual uint8_t Version() const = 0;
    virtual uint8_t Flags() const = 0;
    virtual uint8_t SizeOfProlog() const = 0;
    virtual uint8_t CountOfCodes() const = 0;
    virtual uint8_t FrameRegister() const = 0;
    virtual uint8_t FrameOffset() const = 0;

    virtual const std::vector<std::unique_ptr<const UnwindCode>>& codes() const = 0;

    virtual bool is_chained() const = 0;
    const RUNTIME_FUNCTION* chained_function(const IMAGE_EXCEPTION_SECTION* pdata) const;

    virtual uint32_t exception_handler_rva() const = 0;

    virtual ~UnwindInfo() = default;
};

} /* namespace pe */
} /* namespace windows */
} /* namespace introvirt */
