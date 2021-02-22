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
#include <introvirt/windows/kernel/nt/fwd.hh>

#include <cstdint>
#include <memory>
#include <vector>

namespace introvirt {
namespace windows {
namespace nt {

/**
 * Holds lists of modules for this PEB
 */
class PEB_LDR_DATA {
  public:
    /**
     * @returns The list of loaded modules, in the order in which they were loaded
     */
    virtual const std::vector<std::shared_ptr<const LDR_DATA_TABLE_ENTRY>>&
    InLoadOrderList() const = 0;

    virtual ~PEB_LDR_DATA() = default;
};

} /* namespace nt */
} /* namespace windows */
} /* namespace introvirt */
