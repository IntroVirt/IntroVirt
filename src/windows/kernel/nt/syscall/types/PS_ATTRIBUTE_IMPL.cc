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
#include "PS_ATTRIBUTE_IMPL.hh"

#include "windows/kernel/nt/types/CLIENT_ID_IMPL.hh"

#include <introvirt/windows/common/WStr.hh>

#include <boost/io/ios_state.hpp>

namespace introvirt {
namespace windows {
namespace nt {

template <typename PtrType>
void PS_ATTRIBUTE_IMPL<PtrType>::write(std::ostream& os, const std::string& linePrefix) const {
    boost::io::ios_flags_saver ifs(os);
    os << std::hex;

    // Print out the basic information
    os << linePrefix << AttributeNumber() << ": 0x" << Value() << '\n';

    // Handle special cases with extra information
    switch (AttributeNumber()) {
    case PS_ATTRIBUTE_NUM::PsAttributeClientId:
        // TODO: Create a PsAttributeClientId to hold this
        if (Value() != 0u) {
            CLIENT_ID_IMPL<PtrType> cid(gva_.create(Value()));
            cid.write(os, linePrefix + "  ");
        }
        break;
    case PS_ATTRIBUTE_NUM::PsAttributeImageName: {
        // TODO: Create a PsAttributeImageName class to hold this
        WStr imageName(address().create(Value()), Size());
        os << linePrefix << "  " << imageName << '\n';
        break;
    }
    case PS_ATTRIBUTE_NUM::PsAttributeParentProcess:
    case PS_ATTRIBUTE_NUM::PsAttributeDebugPort:
    case PS_ATTRIBUTE_NUM::PsAttributeToken:
    case PS_ATTRIBUTE_NUM::PsAttributeTebAddress:
    case PS_ATTRIBUTE_NUM::PsAttributeImageInfo:
    case PS_ATTRIBUTE_NUM::PsAttributeMemoryReserve:
    case PS_ATTRIBUTE_NUM::PsAttributePriorityClass:
    case PS_ATTRIBUTE_NUM::PsAttributeErrorMode:
    case PS_ATTRIBUTE_NUM::PsAttributeStdHandleInfo:
    case PS_ATTRIBUTE_NUM::PsAttributeHandleList:
    case PS_ATTRIBUTE_NUM::PsAttributeGroupAffinity:
    case PS_ATTRIBUTE_NUM::PsAttributePreferredNode:
    case PS_ATTRIBUTE_NUM::PsAttributeIdealProcessor:
    case PS_ATTRIBUTE_NUM::PsAttributeUmsThread:
    case PS_ATTRIBUTE_NUM::PsAttributeMitigationOptions:
    case PS_ATTRIBUTE_NUM::PsAttributeSecurityCapabilities:
    case PS_ATTRIBUTE_NUM::PsAttributeJobList:
    case PS_ATTRIBUTE_NUM::PsAttributeMax: /* Not a real value */
        break;
    }
}

template <typename PtrType>
Json::Value PS_ATTRIBUTE_IMPL<PtrType>::json() const {
    Json::Value result;

    result["AttributeNumber"] = to_string(AttributeNumber());

    // Handle special cases with extra information
    switch (AttributeNumber()) {
    case PS_ATTRIBUTE_NUM::PsAttributeClientId:
        // TODO: Create a PsAttributeClientId to hold this
#if 0
            // TODO
            if ((Value() != 0u) && !nthandler->getResult().NT_ERROR()) {
                CLIENT_ID cid(event.getVCPU(), event.getWinCfg(), Value());
                result["value"] = cid.json();
            }
#endif
        break;
    case PS_ATTRIBUTE_NUM::PsAttributeImageName: {
        // TODO: Create a PsAttributeImageName class to hold this
        WStr imageName(address().create(Value()), Size());
        result["Value"] = imageName.utf8();
        break;
    }
    case PS_ATTRIBUTE_NUM::PsAttributeParentProcess:
    case PS_ATTRIBUTE_NUM::PsAttributeDebugPort:
    case PS_ATTRIBUTE_NUM::PsAttributeToken:
    case PS_ATTRIBUTE_NUM::PsAttributeTebAddress:
    case PS_ATTRIBUTE_NUM::PsAttributeImageInfo:
    case PS_ATTRIBUTE_NUM::PsAttributeMemoryReserve:
    case PS_ATTRIBUTE_NUM::PsAttributePriorityClass:
    case PS_ATTRIBUTE_NUM::PsAttributeErrorMode:
    case PS_ATTRIBUTE_NUM::PsAttributeStdHandleInfo:
    case PS_ATTRIBUTE_NUM::PsAttributeHandleList:
    case PS_ATTRIBUTE_NUM::PsAttributeGroupAffinity:
    case PS_ATTRIBUTE_NUM::PsAttributePreferredNode:
    case PS_ATTRIBUTE_NUM::PsAttributeIdealProcessor:
    case PS_ATTRIBUTE_NUM::PsAttributeUmsThread:
    case PS_ATTRIBUTE_NUM::PsAttributeMitigationOptions:
    case PS_ATTRIBUTE_NUM::PsAttributeSecurityCapabilities:
    case PS_ATTRIBUTE_NUM::PsAttributeJobList:
    case PS_ATTRIBUTE_NUM::PsAttributeMax: /* Not a real value */
        result["Value"] = Value();
        break;
    }

    return result;
}

const std::string& to_string(PS_ATTRIBUTE_NUM attribute) {
    static const std::string PsAttributeParentProcessStr("PsAttributeParentProcess");
    static const std::string PsAttributeDebugPortStr("PsAttributeDebugPort");
    static const std::string PsAttributeTokenStr("PsAttributeToken");
    static const std::string PsAttributeClientIdStr("PsAttributeClientId");
    static const std::string PsAttributeTebAddressStr("PsAttributeTebAddress");
    static const std::string PsAttributeImageNameStr("PsAttributeImageName");
    static const std::string PsAttributeImageInfoStr("PsAttributeImageInfo");
    static const std::string PsAttributeMemoryReserveStr("PsAttributeMemoryReserve");
    static const std::string PsAttributePriorityClassStr("PsAttributePriorityClass");
    static const std::string PsAttributeErrorModeStr("PsAttributeErrorMode");
    static const std::string PsAttributeStdHandleInfoStr("PsAttributeStdHandleInfo");
    static const std::string PsAttributeHandleListStr("PsAttributeHandleList");
    static const std::string PsAttributeGroupAffinityStr("PsAttributeGroupAffinity");
    static const std::string PsAttributePreferredNodeStr("PsAttributePreferredNode");
    static const std::string PsAttributeIdealProcessorStr("PsAttributeIdealProcessor");
    static const std::string PsAttributeUmsThreadStr("PsAttributeUmsThread");
    static const std::string PsAttributeMitigationOptionsStr("PsAttributeMitigationOptions");
    static const std::string PsAttributeProtectionLevelStr("PsAttributeProtectionLevel");
    static const std::string PsAttributeSecurityCapabilitiesStr("PsAttributeSecurityCapabilities");
    static const std::string PsAttributeJobListStr("PsAttributeJobList");

    static const std::string PsAttributeChildProcessPolicyStr("PsAttributeChildProcessPolicy");
    static const std::string PsAttributeAllApplicationPackagesPolicyStr(
        "PsAttributeAllApplicationPackagesPolicy");
    static const std::string PsAttributeWin32kFilterStr("PsAttributeWin32kFilter");
    static const std::string PsAttributeSafeOpenPromptOriginClaimStr(
        "PsAttributeSafeOpenPromptOriginClaim");
    static const std::string PsAttributeBnoIsolationStr("PsAttributeBnoIsolation");
    static const std::string PsAttributeDesktopAppPolicyStr("PsAttributeDesktopAppPolicy");
    static const std::string PsAttributeChpeStr("PsAttributeChpe");

    static const std::string UnknownAttributeStr("Unknown");

    switch (attribute) {
    case PS_ATTRIBUTE_NUM::PsAttributeParentProcess:
        return PsAttributeParentProcessStr;
    case PS_ATTRIBUTE_NUM::PsAttributeDebugPort:
        return PsAttributeDebugPortStr;
    case PS_ATTRIBUTE_NUM::PsAttributeToken:
        return PsAttributeTokenStr;
    case PS_ATTRIBUTE_NUM::PsAttributeClientId:
        return PsAttributeClientIdStr;
    case PS_ATTRIBUTE_NUM::PsAttributeTebAddress:
        return PsAttributeTebAddressStr;
    case PS_ATTRIBUTE_NUM::PsAttributeImageName:
        return PsAttributeImageNameStr;
    case PS_ATTRIBUTE_NUM::PsAttributeImageInfo:
        return PsAttributeImageInfoStr;
    case PS_ATTRIBUTE_NUM::PsAttributeMemoryReserve:
        return PsAttributeMemoryReserveStr;
    case PS_ATTRIBUTE_NUM::PsAttributePriorityClass:
        return PsAttributePriorityClassStr;
    case PS_ATTRIBUTE_NUM::PsAttributeErrorMode:
        return PsAttributeErrorModeStr;
    case PS_ATTRIBUTE_NUM::PsAttributeStdHandleInfo:
        return PsAttributeStdHandleInfoStr;
    case PS_ATTRIBUTE_NUM::PsAttributeHandleList:
        return PsAttributeHandleListStr;
    case PS_ATTRIBUTE_NUM::PsAttributeGroupAffinity:
        return PsAttributeGroupAffinityStr;
    case PS_ATTRIBUTE_NUM::PsAttributePreferredNode:
        return PsAttributePreferredNodeStr;
    case PS_ATTRIBUTE_NUM::PsAttributeIdealProcessor:
        return PsAttributeIdealProcessorStr;
    case PS_ATTRIBUTE_NUM::PsAttributeUmsThread:
        return PsAttributeUmsThreadStr;
    case PS_ATTRIBUTE_NUM::PsAttributeMitigationOptions:
        return PsAttributeMitigationOptionsStr;
    case PS_ATTRIBUTE_NUM::PsAttributeProtectionLevel:
        return PsAttributeProtectionLevelStr;
    case PS_ATTRIBUTE_NUM::PsAttributeSecurityCapabilities:
        return PsAttributeSecurityCapabilitiesStr;
    case PS_ATTRIBUTE_NUM::PsAttributeJobList:
        return PsAttributeJobListStr;
    case PS_ATTRIBUTE_NUM::PsAttributeChildProcessPolicy:
        return PsAttributeChildProcessPolicyStr;
    case PS_ATTRIBUTE_NUM::PsAttributeAllApplicationPackagesPolicy:
        return PsAttributeAllApplicationPackagesPolicyStr;
    case PS_ATTRIBUTE_NUM::PsAttributeWin32kFilter:
        return PsAttributeWin32kFilterStr;
    case PS_ATTRIBUTE_NUM::PsAttributeSafeOpenPromptOriginClaim:
        return PsAttributeSafeOpenPromptOriginClaimStr;
    case PS_ATTRIBUTE_NUM::PsAttributeBnoIsolation:
        return PsAttributeBnoIsolationStr;
    case PS_ATTRIBUTE_NUM::PsAttributeDesktopAppPolicy:
        return PsAttributeDesktopAppPolicyStr;
    case PS_ATTRIBUTE_NUM::PsAttributeChpe:
        return PsAttributeChpeStr;
    case PS_ATTRIBUTE_NUM::PsAttributeMax:
        return UnknownAttributeStr;
    }

    return UnknownAttributeStr;
}

std::ostream& operator<<(std::ostream& os, PS_ATTRIBUTE_NUM attribute) {
    os << to_string(attribute);
    return os;
}

template class PS_ATTRIBUTE_IMPL<uint32_t>;
template class PS_ATTRIBUTE_IMPL<uint64_t>;

} // namespace nt
} // namespace windows
} // namespace introvirt