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

#include "SYSTEM_INFORMATION.hh"

namespace introvirt {
namespace windows {
namespace nt {

class SYSTEM_PROCESSOR_INFORMATION : public SYSTEM_INFORMATION {
  public:
    virtual uint16_t ProcessorArchitecture() const = 0;
    virtual void ProcessorArchitecture(uint16_t ProcessorArchitecture) = 0;

    virtual uint16_t ProcessorLevel() const = 0;
    virtual void ProcessorLevel(uint16_t ProcessorLevel) = 0;

    virtual uint16_t ProcessorRevision() const = 0;
    virtual void ProcessorRevision(uint16_t ProcessorRevision) = 0;

    virtual uint16_t MaximumProcessors() const = 0;
    virtual void MaximumProcessors(uint16_t MaximumProcessors) = 0;

    virtual uint32_t ProcessorFeatureBits() const = 0;
    virtual void ProcessorFeatureBits(uint32_t ProcessorFeatureBits) = 0;
};

} // namespace nt
} // namespace windows
} // namespace introvirt
