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

#include "FILE_INFO.hh"

#include <introvirt/core/fwd.hh>

#include <cstdint>
#include <map>
#include <memory>
#include <string>

namespace introvirt {
namespace windows {
namespace pe {

/**
 * @see https://docs.microsoft.com/en-us/windows/win32/menurc/stringtable
 */
class StringTable : public FILE_INFO {
  public:
    virtual uint16_t language_identifier() const = 0;
    virtual uint16_t code_page() const = 0;
    virtual const std::map<std::string, std::string>& entries() const = 0;
};

} /* namespace pe */
} /* namespace windows */
} /* namespace introvirt */
