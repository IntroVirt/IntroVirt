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
#include "gitversion.h"
#include <introvirt/VersionInfo.hh>

/*
 * If the GIT_VERSION isn't available, use the one provided by automake
 */
#ifndef GIT_VERSION
#define GIT_VERSION VERSION
#endif

namespace introvirt {

std::string VersionInfo::version() {
    const static std::string VersionString = GIT_VERSION;
    return VersionString;
}

bool VersionInfo::is_debug_build() {
#ifdef NDEBUG
    return false;
#else
    return true;
#endif
}
bool VersionInfo::is_optimized_build() {
#ifdef __OPTIMIZE__
    return true;
#else
    return false;
#endif
}

VersionInfo::VersionInfo() = default;

} // namespace introvirt
