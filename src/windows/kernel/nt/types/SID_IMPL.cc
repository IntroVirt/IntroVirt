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
#include "SID_IMPL.hh"

#include <introvirt/windows/kernel/nt/NtKernel.hh>

#include <algorithm>
#include <sstream>

namespace introvirt {
namespace windows {
namespace nt {

Json::Value SID_IMPL::json() const {
    Json::Value result;

    result["Revision"] = Revision();
    result["value"] = to_string(*this);

    // TODO: This is weird
    const std::string identifierAuthority(
        reinterpret_cast<const char*>(pIdentifierAuthority_.get()), pIdentifierAuthority_.length());

    result["IdentifierAuthority"] = identifierAuthority;

    for (uint32_t SubAuthority : SubAuthorities()) {
        result["SubAuthorities"].append(SubAuthority);
    }

    return result;
}

std::string to_string(const SID& sid) {
    std::stringstream ss;
    ss << sid;
    return ss.str();
}

std::ostream& operator<<(std::ostream& os, const SID& sid) {
    os << "S-" << static_cast<int>(sid.Revision()) << '-';

    auto pIdentifierAuthority = sid.IdentifierAuthority();
    for (size_t i = pIdentifierAuthority.length(); i > 0; --i) {
        uint8_t byte = pIdentifierAuthority[i - 1];
        if (byte != 0u) {
            os << static_cast<unsigned int>(byte);
        }
    }

    auto pSubAuthorities = sid.SubAuthorities();
    for (uint32_t SubAuthority : sid.SubAuthorities()) {
        os << "-" << SubAuthority;
    }

    return os;
}

} // namespace nt
} // namespace windows
} // namespace introvirt
