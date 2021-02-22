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
#include <introvirt/windows/kernel/nt/types/access_mask/MUTANT_ACCESS_MASK.hh>
#include <sstream>

namespace introvirt {
namespace windows {
namespace nt {

const std::string& to_string(MutantAccessMaskFlag flag) {
    static const std::string MUTANT_QUERY_STATE_STR("MUTANT_QUERY_STATE");
    static const std::string MUTANT_ALL_ACCESS_STR("MUTANT_ALL_ACCESS");
    static const std::string UNKNOWN_STR("UNKNOWN");

    switch (flag) {
    case MutantAccessMaskFlag::MUTANT_QUERY_STATE:
        return MUTANT_QUERY_STATE_STR;
    case MutantAccessMaskFlag::MUTANT_ALL_ACCESS:
        return MUTANT_ALL_ACCESS_STR;
    }

    return UNKNOWN_STR;
}

std::ostream& operator<<(std::ostream& os, MutantAccessMaskFlag flag) {
    os << to_string(flag);
    return os;
}

std::string to_string(MUTANT_ACCESS_MASK mask) {
    std::ostringstream ss;
    ss << mask;
    return ss.str();
}

#define WRITE_IF_ENABLED(flag)                                                                     \
    if (mask.has(flag)) {                                                                          \
        os << to_string(flag) << ' ';                                                              \
        mask.clear(flag);                                                                          \
    }

std::ostream& operator<<(std::ostream& os, MUTANT_ACCESS_MASK mask) {
    WRITE_IF_ENABLED(MutantAccessMaskFlag::MUTANT_QUERY_STATE);
    WRITE_IF_ENABLED(MutantAccessMaskFlag::MUTANT_ALL_ACCESS);

    // Now call the base class to handle any remaining bits
    ACCESS_MASK base(mask.value());
    os << base;

    return os;
}

} /* namespace nt */
} /* namespace windows */
} /* namespace introvirt */
