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

#include "OBJECT.hh"

#include <cstdint>
#include <memory>
#include <vector>

namespace introvirt {
namespace windows {
namespace nt {

enum SePrivilege {
    SeUnsolicitedInputPrivilege = 0x0,
    SeCreateTokenPrivilege = 0x2,
    SeAssignPrimaryTokenPrivilege = 0x3,
    SeLockMemoryPrivilege = 0x4,
    SeIncreaseQuotaPrivilege = 0x5,
    SeMachineAccountPrivilege = 0x6,
    SeTcbPrivilege = 0x7,
    SeSecurityPrivilege = 0x8,
    SeTakeOwnershipPrivilege = 0x9,
    SeLoadDriverPrivilege = 0xa,
    SeSystemProfilePrivilege = 0xb,
    SeSystemtimePrivilege = 0xc,
    SeProfileSingleProcessPrivilege = 0xd,
    SeIncreaseBasePriorityPrivilege = 0xe,
    SeCreatePagefilePrivilege = 0xf,
    SeCreatePermanentPrivilege = 0x10,
    SeBackupPrivilege = 0x11,
    SeRestorePrivilege = 0x12,
    SeShutdownPrivilege = 0x13,
    SeDebugPrivilege = 0x14,
    SeAuditPrivilege = 0x15,
    SeSystemEnvironmentPrivilege = 0x16,
    SeChangeNotifyPrivilege = 0x17,
    SeRemoteShutdownPrivilege = 0x18,
    SeUndockPrivilege = 0x19,
    SeSyncAgentPrivilege = 0x1a,
    SeEnableDelegationPrivilege = 0x1b,
    SeManageVolumePrivilege = 0x1c,
    SeImpersonatePrivilege = 0x1d,
    SeCreateGlobalPrivilege = 0x1e,
    SeTrustedCredManAccessPrivilege = 0x1f,
    SeRelabelPrivilege = 0x20,
    SeIncreaseWorkingSetPrivilege = 0x21,
    SeTimeZonePrivilege = 0x22,
    SeCreateSymbolicLinkPrivilege = 0x23
};

class TOKEN : public OBJECT {
  public:
    virtual std::vector<std::shared_ptr<SID_AND_ATTRIBUTES>> Groups() = 0;
    virtual std::vector<std::shared_ptr<const SID_AND_ATTRIBUTES>> Groups() const = 0;

    virtual const SID* User() const = 0;
    virtual const SID* PrimaryGroup() const = 0;

    virtual uint64_t PrivilegesPresent() const = 0;
    virtual void PrivilegesPresent(uint64_t Privileges) = 0;

    virtual uint64_t PrivilegesEnabled() const = 0;
    virtual void PrivilegesEnabled(uint64_t Privileges) = 0;

    static std::shared_ptr<TOKEN> make_shared(const NtKernel& kernel,
                                              const GuestVirtualAddress& gva);

    static std::shared_ptr<TOKEN> make_shared(const NtKernel& kernel,
                                              std::unique_ptr<OBJECT_HEADER>&& object_header);

    virtual ~TOKEN() = default;
};

} /* namespace nt */
} /* namespace windows */
} /* namespace introvirt */
