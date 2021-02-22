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

#include <introvirt/windows/kernel/nt/syscall/types/token_information/TOKEN_INFORMATION_CLASS.hh>

namespace introvirt {
namespace windows {
namespace nt {

const std::string& to_string(TOKEN_INFORMATION_CLASS infoClass) {
    static const std::string TokenUserStr("TokenUser");
    static const std::string TokenGroupsStr("TokenGroups");
    static const std::string TokenPrivilegesStr("TokenPrivileges");
    static const std::string TokenOwnerStr("TokenOwner");
    static const std::string TokenPrimaryGroupStr("TokenPrimaryGroup");
    static const std::string TokenDefaultDaclStr("TokenDefaultDacl");
    static const std::string TokenSourceStr("TokenSource");
    static const std::string TokenTypeStr("TokenType");
    static const std::string TokenImpersonationLevelStr("TokenImpersonationLevel");
    static const std::string TokenStatisticsStr("TokenStatistics");
    static const std::string TokenRestrictedSidsStr("TokenRestrictedSids");
    static const std::string TokenSessionIdStr("TokenSessionId");
    static const std::string TokenGroupsAndPrivilegesStr("TokenGroupsAndPrivileges");
    static const std::string TokenSessionReferenceStr("TokenSessionReference");
    static const std::string TokenSandBoxInertStr("TokenSandBoxInert");
    static const std::string TokenAuditPolicyStr("TokenAuditPolicy");
    static const std::string TokenOriginStr("TokenOrigin");
    static const std::string TokenElevationTypeStr("TokenElevationType");
    static const std::string TokenLinkedTokenStr("TokenLinkedToken");
    static const std::string TokenElevationStr("TokenElevation");
    static const std::string TokenHasRestrictionsStr("TokenHasRestrictions");
    static const std::string TokenAccessInformationStr("TokenAccessInformation");
    static const std::string TokenVirtualizationAllowedStr("TokenVirtualizationAllowed");
    static const std::string TokenVirtualizationEnabledStr("TokenVirtualizationEnabled");
    static const std::string TokenIntegrityLevelStr("TokenIntegrityLevel");
    static const std::string TokenUIAccessStr("TokenUIAccess");
    static const std::string TokenMandatoryPolicyStr("TokenMandatoryPolicy");
    static const std::string TokenLogonSidStr("TokenLogonSid");
    static const std::string TokenIsAppContainerStr("TokenIsAppContainer");
    static const std::string TokenCapabilitiesStr("TokenCapabilities");
    static const std::string TokenAppContainerSidStr("TokenAppContainerSid");
    static const std::string TokenAppContainerNumberStr("TokenAppContainerNumber");
    static const std::string TokenUserClaimAttributesStr("TokenUserClaimAttributes");
    static const std::string TokenDeviceClaimAttributesStr("TokenDeviceClaimAttributes");
    static const std::string TokenRestrictedUserClaimAttributesStr(
        "TokenRestrictedUserClaimAttributes");
    static const std::string TokenRestrictedDeviceClaimAttributesStr(
        "TokenRestrictedDeviceClaimAttributes");
    static const std::string TokenDeviceGroupsStr("TokenDeviceGroups");
    static const std::string TokenRestrictedDeviceGroupsStr("TokenRestrictedDeviceGroups");
    static const std::string TokenSecurityAttributesStr("TokenSecurityAttributes");
    static const std::string TokenIsRestrictedStr("TokenIsRestricted");
    static const std::string TokenProcessTrustLevelStr("TokenProcessTrustLevel");
    static const std::string TokenPrivateNameSpaceStr("TokenPrivateNameSpace");
    static const std::string TokenSingletonAttributesStr("TokenSingletonAttributes");
    static const std::string TokenBnoIsolationStr("TokenBnoIsolation");
    static const std::string TokenChildProcessFlagsStr("TokenChildProcessFlags");
    static const std::string TokenIsLessPrivilegedAppContainerStr(
        "TokenIsLessPrivilegedAppContainer");
    static const std::string TokenIsSandboxedStr("TokenIsSandboxed");
    static const std::string TokenOriginatingProcessTrustLevelStr(
        "TokenOriginatingProcessTrustLevel");
    static const std::string Unknown("Unknown");

    switch (infoClass) {
    case TOKEN_INFORMATION_CLASS::TokenUser:
        return TokenUserStr;
    case TOKEN_INFORMATION_CLASS::TokenGroups:
        return TokenGroupsStr;
    case TOKEN_INFORMATION_CLASS::TokenPrivileges:
        return TokenPrivilegesStr;
    case TOKEN_INFORMATION_CLASS::TokenOwner:
        return TokenOwnerStr;
    case TOKEN_INFORMATION_CLASS::TokenPrimaryGroup:
        return TokenPrimaryGroupStr;
    case TOKEN_INFORMATION_CLASS::TokenDefaultDacl:
        return TokenDefaultDaclStr;
    case TOKEN_INFORMATION_CLASS::TokenSource:
        return TokenSourceStr;
    case TOKEN_INFORMATION_CLASS::TokenType:
        return TokenTypeStr;
    case TOKEN_INFORMATION_CLASS::TokenImpersonationLevel:
        return TokenImpersonationLevelStr;
    case TOKEN_INFORMATION_CLASS::TokenStatistics:
        return TokenStatisticsStr;
    case TOKEN_INFORMATION_CLASS::TokenRestrictedSids:
        return TokenRestrictedSidsStr;
    case TOKEN_INFORMATION_CLASS::TokenSessionId:
        return TokenSessionIdStr;
    case TOKEN_INFORMATION_CLASS::TokenGroupsAndPrivileges:
        return TokenGroupsAndPrivilegesStr;
    case TOKEN_INFORMATION_CLASS::TokenSessionReference:
        return TokenSessionReferenceStr;
    case TOKEN_INFORMATION_CLASS::TokenSandBoxInert:
        return TokenSandBoxInertStr;
    case TOKEN_INFORMATION_CLASS::TokenAuditPolicy:
        return TokenAuditPolicyStr;
    case TOKEN_INFORMATION_CLASS::TokenOrigin:
        return TokenOriginStr;
    case TOKEN_INFORMATION_CLASS::TokenElevationType:
        return TokenElevationTypeStr;
    case TOKEN_INFORMATION_CLASS::TokenLinkedToken:
        return TokenLinkedTokenStr;
    case TOKEN_INFORMATION_CLASS::TokenElevation:
        return TokenElevationStr;
    case TOKEN_INFORMATION_CLASS::TokenHasRestrictions:
        return TokenHasRestrictionsStr;
    case TOKEN_INFORMATION_CLASS::TokenAccessInformation:
        return TokenAccessInformationStr;
    case TOKEN_INFORMATION_CLASS::TokenVirtualizationAllowed:
        return TokenVirtualizationAllowedStr;
    case TOKEN_INFORMATION_CLASS::TokenVirtualizationEnabled:
        return TokenVirtualizationEnabledStr;
    case TOKEN_INFORMATION_CLASS::TokenIntegrityLevel:
        return TokenIntegrityLevelStr;
    case TOKEN_INFORMATION_CLASS::TokenUIAccess:
        return TokenUIAccessStr;
    case TOKEN_INFORMATION_CLASS::TokenMandatoryPolicy:
        return TokenMandatoryPolicyStr;
    case TOKEN_INFORMATION_CLASS::TokenLogonSid:
        return TokenLogonSidStr;
    case TOKEN_INFORMATION_CLASS::TokenIsAppContainer:
        return TokenIsAppContainerStr;
    case TOKEN_INFORMATION_CLASS::TokenCapabilities:
        return TokenCapabilitiesStr;
    case TOKEN_INFORMATION_CLASS::TokenAppContainerSid:
        return TokenAppContainerSidStr;
    case TOKEN_INFORMATION_CLASS::TokenAppContainerNumber:
        return TokenAppContainerNumberStr;
    case TOKEN_INFORMATION_CLASS::TokenUserClaimAttributes:
        return TokenUserClaimAttributesStr;
    case TOKEN_INFORMATION_CLASS::TokenDeviceClaimAttributes:
        return TokenDeviceClaimAttributesStr;
    case TOKEN_INFORMATION_CLASS::TokenRestrictedUserClaimAttributes:
        return TokenRestrictedUserClaimAttributesStr;
    case TOKEN_INFORMATION_CLASS::TokenRestrictedDeviceClaimAttributes:
        return TokenRestrictedDeviceClaimAttributesStr;
    case TOKEN_INFORMATION_CLASS::TokenDeviceGroups:
        return TokenDeviceGroupsStr;
    case TOKEN_INFORMATION_CLASS::TokenRestrictedDeviceGroups:
        return TokenRestrictedDeviceGroupsStr;
    case TOKEN_INFORMATION_CLASS::TokenSecurityAttributes:
        return TokenSecurityAttributesStr;
    case TOKEN_INFORMATION_CLASS::TokenIsRestricted:
        return TokenIsRestrictedStr;
    case TOKEN_INFORMATION_CLASS::TokenProcessTrustLevel:
        return TokenProcessTrustLevelStr;
    case TOKEN_INFORMATION_CLASS::TokenPrivateNameSpace:
        return TokenPrivateNameSpaceStr;
    case TOKEN_INFORMATION_CLASS::TokenSingletonAttributes:
        return TokenSingletonAttributesStr;
    case TOKEN_INFORMATION_CLASS::TokenBnoIsolation:
        return TokenBnoIsolationStr;
    case TOKEN_INFORMATION_CLASS::TokenChildProcessFlags:
        return TokenChildProcessFlagsStr;
    case TOKEN_INFORMATION_CLASS::TokenIsLessPrivilegedAppContainer:
        return TokenIsLessPrivilegedAppContainerStr;
    case TOKEN_INFORMATION_CLASS::TokenIsSandboxed:
        return TokenIsSandboxedStr;
    case TOKEN_INFORMATION_CLASS::TokenOriginatingProcessTrustLevel:
        return TokenOriginatingProcessTrustLevelStr;
    }

    return Unknown;
}

std::ostream& operator<<(std::ostream& os, TOKEN_INFORMATION_CLASS infoClass) {
    os << to_string(infoClass);
    return os;
}

} /* namespace nt */
} /* namespace windows */
} /* namespace introvirt */
