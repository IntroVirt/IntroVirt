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

#include <introvirt/windows/pe/types/IMAGE_THUNK_DATA.hh>

#include <introvirt/fwd.hh>

#include <cstdint>
#include <memory>
#include <string>
#include <vector>

namespace introvirt {
namespace windows {
namespace pe {

class IMAGE_IMPORT_DESCRIPTOR {
  public:
    virtual const std::vector<std::unique_ptr<const IMAGE_THUNK_DATA>>&
    ImportedFunctions() const = 0;

    virtual const std::string& ModuleName() const = 0;

    virtual ~IMAGE_IMPORT_DESCRIPTOR() = default;
};

} // namespace pe
} // namespace windows
} // namespace introvirt