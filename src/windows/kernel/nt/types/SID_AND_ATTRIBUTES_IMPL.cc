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
#include "SID_AND_ATTRIBUTES_IMPL.hh"

#include <introvirt/windows/kernel/nt/NtKernel.hh>

#include <log4cxx/logger.h>

static log4cxx::LoggerPtr
    logger(log4cxx::Logger::getLogger("introvirt.windows.kernel.nt.types.SID_AND_ATTRIBUTES"));

namespace introvirt {
namespace windows {
namespace nt {

template <typename PtrType>
GuestVirtualAddress SID_AND_ATTRIBUTES_IMPL<PtrType>::SidPtr() const {
    return gva_.create(data_->Sid);
}

template <typename PtrType>
void SID_AND_ATTRIBUTES_IMPL<PtrType>::SidPtr(const GuestVirtualAddress& gva) {
    data_->Sid = gva.value();
    sid.reset();
}

template <typename PtrType>
SID_AND_ATTRIBUTES::SidAttributeFlags SID_AND_ATTRIBUTES_IMPL<PtrType>::Attributes() const {
    return SidAttributeFlags(data_->Attributes);
}

template <typename PtrType>
void SID_AND_ATTRIBUTES_IMPL<PtrType>::Attributes(SidAttributeFlags Attributes) {
    data_->Attributes = Attributes;
}

template <typename PtrType>
const SID* SID_AND_ATTRIBUTES_IMPL<PtrType>::Sid() const {
    if (sid) {
        return &(*sid);
    }

    // TODO: Can this actually happen?
    return nullptr;
}

template <typename PtrType>
SID_AND_ATTRIBUTES_IMPL<PtrType>::SID_AND_ATTRIBUTES_IMPL(const GuestVirtualAddress& gva)
    : gva_(gva), data_(gva) {

    const auto pSid = SidPtr();
    if (pSid)
        sid.emplace(pSid);
}

template <typename PtrType>
Json::Value SID_AND_ATTRIBUTES_IMPL<PtrType>::json() const {
    Json::Value result;
    result["SID"] = Sid()->json();
    result["Attributes"] = Attributes().value();
    return result;
}

bool SID_AND_ATTRIBUTES::SidAttributeFlags::SE_GROUP_MANDATORY() const {
    return value_ & SID_AND_ATTRIBUTES_FLAGS::SE_GROUP_MANDATORY;
}

bool SID_AND_ATTRIBUTES::SidAttributeFlags::SE_GROUP_ENABLED_BY_DEFAULT() const {
    return value_ & SID_AND_ATTRIBUTES_FLAGS::SE_GROUP_ENABLED_BY_DEFAULT;
}

bool SID_AND_ATTRIBUTES::SidAttributeFlags::SE_GROUP_ENABLED() const {
    return value_ & SID_AND_ATTRIBUTES_FLAGS::SE_GROUP_ENABLED;
}

bool SID_AND_ATTRIBUTES::SidAttributeFlags::SE_GROUP_OWNER() const {
    return value_ & SID_AND_ATTRIBUTES_FLAGS::SE_GROUP_OWNER;
}

bool SID_AND_ATTRIBUTES::SidAttributeFlags::SE_GROUP_USE_FOR_DENY_ONLY() const {
    return value_ & SID_AND_ATTRIBUTES_FLAGS::SE_GROUP_USE_FOR_DENY_ONLY;
}

bool SID_AND_ATTRIBUTES::SidAttributeFlags::SE_GROUP_INTEGRITY() const {
    return value_ & SID_AND_ATTRIBUTES_FLAGS::SE_GROUP_INTEGRITY;
}

bool SID_AND_ATTRIBUTES::SidAttributeFlags::SE_GROUP_INTEGRITY_ENABLED() const {
    return value_ & SID_AND_ATTRIBUTES_FLAGS::SE_GROUP_INTEGRITY_ENABLED;
}

bool SID_AND_ATTRIBUTES::SidAttributeFlags::SE_GROUP_RESOURCE() const {
    return value_ & SID_AND_ATTRIBUTES_FLAGS::SE_GROUP_RESOURCE;
}

bool SID_AND_ATTRIBUTES::SidAttributeFlags::SE_GROUP_LOGON_ID() const {
    return value_ & SID_AND_ATTRIBUTES_FLAGS::SE_GROUP_LOGON_ID;
}

std::string SID_AND_ATTRIBUTES::SidAttributeFlags::string() const {
    std::string attributesStr;
    attributesStr.reserve(128);

    if (SE_GROUP_MANDATORY()) {
        attributesStr += "MANDATORY ";
    }
    if (SE_GROUP_ENABLED_BY_DEFAULT()) {
        attributesStr += "ENABLED_BY_DEFAULT ";
    }
    if (SE_GROUP_ENABLED()) {
        attributesStr += "ENABLED ";
    }
    if (SE_GROUP_OWNER()) {
        attributesStr += "OWNER ";
    }
    if (SE_GROUP_USE_FOR_DENY_ONLY()) {
        attributesStr += "USE_FOR_DENY_ONLY ";
    }
    if (SE_GROUP_INTEGRITY()) {
        attributesStr += "INTEGRITY ";
    }
    if (SE_GROUP_INTEGRITY_ENABLED()) {
        attributesStr += "INTEGRITY_ENABLED ";
    }
    if (SE_GROUP_RESOURCE()) {
        attributesStr += "RESOURCE ";
    }
    if (SE_GROUP_LOGON_ID()) {
        attributesStr += "LOGON_ID ";
    }
    return attributesStr;
}

std::string to_string(SID_AND_ATTRIBUTES::SidAttributeFlags flags) { return flags.string(); }

std::ostream& operator<<(std::ostream& os, SID_AND_ATTRIBUTES::SidAttributeFlags flags) {
    os << flags.string();
    return os;
}

std::shared_ptr<SID_AND_ATTRIBUTES>
SID_AND_ATTRIBUTES::make_shared(const NtKernel& kernel, const GuestVirtualAddress& gva) {
    if (kernel.x64())
        return std::make_shared<SID_AND_ATTRIBUTES_IMPL<uint64_t>>(gva);
    else
        return std::make_shared<SID_AND_ATTRIBUTES_IMPL<uint32_t>>(gva);
}

template class SID_AND_ATTRIBUTES_IMPL<uint32_t>;
template class SID_AND_ATTRIBUTES_IMPL<uint64_t>;

} // namespace nt
} // namespace windows
} // namespace introvirt
