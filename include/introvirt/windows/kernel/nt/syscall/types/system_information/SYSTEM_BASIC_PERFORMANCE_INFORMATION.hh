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

class SYSTEM_BASIC_PERFORMANCE_INFORMATION : public SYSTEM_INFORMATION {
  public:
    virtual uint32_t AvailablePages() const = 0;
    virtual void AvailablePages(uint32_t AvailablePages) = 0;

    virtual uint32_t CommittedPages() const = 0;
    virtual void CommittedPages(uint32_t CommittedPages) = 0;

    virtual uint32_t CommitLimit() const = 0;
    virtual void CommitLimit(uint32_t CommitLimit) = 0;

    virtual uint32_t PeakCommitment() const = 0;
    virtual void PeakCommitment(uint32_t PeakCommitment) = 0;
};

} // namespace nt
} // namespace windows
} // namespace introvirt
