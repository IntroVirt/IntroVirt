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

#include <introvirt/windows/pe/const/ImageDebugType.hh>
#include <introvirt/windows/pe/types/CV_INFO.hh>

#include <introvirt/core/memory/GuestVirtualAddress.hh>
#include <introvirt/fwd.hh>

#include <cstdint>
#include <memory>
#include <string>

namespace introvirt {
namespace windows {
namespace pe {

class IMAGE_DEBUG_DIRECTORY {
  public:
    virtual uint32_t Characteristics() const = 0;
    virtual uint32_t TimeDateStamp() const = 0;
    virtual uint16_t MajorVersion() const = 0;
    virtual uint16_t MinorVersion() const = 0;
    virtual ImageDebugType Type() const = 0;

    /**
     * @brief Get the codeview data, if the Type is IMAGE_DEBUG_TYPE_CODEVIEW
     *
     * @return The CV_INFO data, or nullptr if Type is not IMAGE_DEBUG_TYPE_CODEVIEW
     */
    virtual const CV_INFO* codeview_data() const = 0;

    virtual ~IMAGE_DEBUG_DIRECTORY() = default;
};

} /* namespace pe */
} /* namespace windows */
} /* namespace introvirt */
