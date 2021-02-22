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

#include <string>

namespace introvirt {

/**
 * @brief Version information for libintrovirt
 *
 */
class VersionInfo {
  public:
    /**
     * @brief Get the libintrovirt version as a string
     *
     * @return A string containing the library version
     */
    static std::string version();

    /**
     * @brief Check if the library was compiled in debug mode
     *
     * @return true if the library was compiled in debug mode
     * @return false if the library was not compiled in debug mode
     */
    static bool is_debug_build();

    /**
     * @brief Check if the library was compiled with optimizations
     *
     * @return true if the library was compiled with optimizations
     * @return false if the library compiled without optimizations
     */
    static bool is_optimized_build();

  private:
    VersionInfo();
};

} // namespace introvirt
