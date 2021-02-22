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

#include <iostream>
#include <memory>
#include <string>

namespace introvirt {
namespace windows {
namespace nt {

class NtBuildLab {
  public:
    uint32_t MajorBuildNumber() const;

    /**
     * Not always available.
     *
     * @returns The sub build-number
     */
    uint32_t MinorBuildNumber() const;

    uint32_t BuildYear() const;
    uint32_t BuildMonth() const;
    uint32_t BuildDay() const;

    /**
     * @returns the build date in the form of YYMMDD
     */
    uint32_t BuildDate() const;

    /**
     * Not always available.
     * Looks like "amd64fre" or "x86fre".
     *
     * @returns build type information as a string
     */
    std::string BuildType() const;

    std::string BuildLabel() const;

    /**
     * @brief Get the original string
     */
    std::string string() const;

    explicit NtBuildLab(const std::string& str);

    ~NtBuildLab();

  private:
    class IMPL;
    std::unique_ptr<IMPL> pImpl;
};

/**
 * @brief Stream overoad to write NtBuildLab to streams
 */
std::ostream& operator<<(std::ostream&, const NtBuildLab&);

} // namespace nt
} // namespace windows
} // namespace introvirt
