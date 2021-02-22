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

#include "KEY_VALUE_INFORMATION.hh"

#include <introvirt/windows/kernel/nt/const/REG_TYPE.hh>
#include <introvirt/windows/kernel/nt/types/registry/KEY_VALUE.hh>

namespace introvirt {
namespace windows {
namespace nt {

class UNICODE_STRING;

/**
 * @brief Handler for KEY_VALUE_BASIC_INFORMATION
 *
 * This variant contains both Name and Data values
 *
 */
class KEY_VALUE_FULL_INFORMATION : public KEY_VALUE_INFORMATION {
  public:
    virtual const std::string& Name() const = 0;

    /**
     * @brief Set the name parameter
     *
     * @param Name
     */
    virtual void Name(const std::string& Name) = 0;
};

} /* namespace nt */
} /* namespace windows */
} /* namespace introvirt */