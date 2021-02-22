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

#include <cstdint>
#include <string>

namespace introvirt {
namespace windows {
namespace pe {

/**
 * @brief Parser for CodeView debug information
 */
class CV_INFO {
  public:
    virtual uint32_t CvSignature() const = 0;
    virtual const std::string& PdbGUID() const = 0;
    virtual const std::string& PdbIdentifier() const = 0;
    virtual const uint32_t Age() const = 0;
    virtual const std::string& PdbFileName() const = 0;

    virtual ~CV_INFO() = default;
};

} /* namespace pe */
} /* namespace windows */
} /* namespace introvirt */
