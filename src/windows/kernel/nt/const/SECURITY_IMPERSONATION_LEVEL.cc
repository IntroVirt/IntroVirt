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

#include <introvirt/windows/kernel/nt/const/SECURITY_IMPERSONATION_LEVEL.hh>

namespace introvirt {
namespace windows {
namespace nt {

const std::string& to_string(SECURITY_IMPERSONATION_LEVEL level) {
    static const std::string SecurityAnonymousStr("SecurityAnonymous");
    static const std::string SecurityIdentificationStr("SecurityIdentification");
    static const std::string SecurityImpersonationStr("SecurityImpersonation");
    static const std::string SecurityDelegationStr("SecurityDelegation");
    static const std::string SecurityUnknownStr("SecurityUnknown");

    switch (level) {
    case SECURITY_IMPERSONATION_LEVEL::SecurityAnonymous:
        return SecurityAnonymousStr;
    case SECURITY_IMPERSONATION_LEVEL::SecurityIdentification:
        return SecurityIdentificationStr;
    case SECURITY_IMPERSONATION_LEVEL::SecurityImpersonation:
        return SecurityImpersonationStr;
    case SECURITY_IMPERSONATION_LEVEL::SecurityDelegation:
        return SecurityDelegationStr;
    default:
        return SecurityUnknownStr;
    }
}

std::ostream& operator<<(std::ostream& os, SECURITY_IMPERSONATION_LEVEL level) {
    os << to_string(level);
    return os;
}

} // namespace nt
} // namespace windows
} // namespace introvirt
