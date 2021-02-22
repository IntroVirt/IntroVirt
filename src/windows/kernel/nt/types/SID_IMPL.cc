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

#include <log4cxx/logger.h>

#include <algorithm>
#include <sstream>

namespace introvirt {
namespace windows {
namespace nt {

static log4cxx::LoggerPtr
    logger(log4cxx::Logger::getLogger("introvirt.windows.kernel.nt.types.SID"));

uint8_t SID_IMPL::Revision() const { return buffer_->Revision; }

const std::vector<uint8_t>& SID_IMPL::IdentifierAuthority() const { return IdentifierAuthority_; }

const std::vector<uint32_t>& SID_IMPL::SubAuthorities() const { return SubAuthorities_; }

SID_IMPL::SID_IMPL(const GuestVirtualAddress& gva) : gva_(gva), buffer_(gva) {
    // Copy out the IdentifierAuthority into a vector
    std::copy_n(buffer_->IdentifierAuthority.Value, sizeof(buffer_->IdentifierAuthority.Value),
                std::back_inserter(IdentifierAuthority_));

    // Map in the SubAuthority structure
    const uint8_t SubAuthorityCount = buffer_->SubAuthorityCount;
    if (SubAuthorityCount > 0) {
        guest_ptr<uint32_t[]> rawSubAuthorities(gva_ + offsetof(structs::_SID, SubAuthority),
                                                SubAuthorityCount);

        // Copy all of the values into our vector
        std::copy(rawSubAuthorities.begin(), rawSubAuthorities.end(),
                  std::back_inserter(SubAuthorities_));
    }
}

Json::Value SID_IMPL::json() const {
    Json::Value result;

    result["Revision"] = Revision();
    result["value"] = to_string(*this);

    // TODO: This is weird
    const std::string identifierAuthority(
        reinterpret_cast<const char*>(IdentifierAuthority().data()), IdentifierAuthority().size());
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
    const std::vector<uint8_t>& identifierAuthority = sid.IdentifierAuthority();

    for (auto i = identifierAuthority.rbegin(); i != identifierAuthority.rend(); ++i) {
        if (*i != 0u) {
            os << static_cast<unsigned int>(*i);
        }
    }

    for (uint32_t SubAuthority : sid.SubAuthorities()) {
        os << "-" << SubAuthority;
    }

    return os;
}

} // namespace nt
} // namespace windows
} // namespace introvirt
