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

#include "SECURITY_QUALITY_OF_SERVICE_IMPL.hh"

#include "windows/kernel/nt/structs/structs.hh"
#include "windows/kernel/nt/syscall/types/SECURITY_DESCRIPTOR_IMPL.hh"
#include "windows/kernel/nt/types/UNICODE_STRING_IMPL.hh"

#include <introvirt/core/memory/guest_ptr.hh>
#include <introvirt/windows/kernel/nt/syscall/types/OBJECT_ATTRIBUTES.hh>

#include <optional>

namespace introvirt {
namespace windows {
namespace nt {

namespace structs {

template <typename PtrType>
struct _OBJECT_ATTRIBUTES {
    uint32_t Length;
    PtrType RootDirectory;
    PtrType ObjectName;
    uint32_t Attributes;
    PtrType SecurityDescriptor;
    PtrType SecurityQualityOfService;
} __attribute__((aligned(sizeof(PtrType))));

static_assert(sizeof(_OBJECT_ATTRIBUTES<uint32_t>) == 0x18);
static_assert(sizeof(_OBJECT_ATTRIBUTES<uint64_t>) == 0x30);

} // namespace structs

template <typename PtrType>
class OBJECT_ATTRIBUTES_IMPL final : public OBJECT_ATTRIBUTES {
  public:
    uint32_t Length() const override;

    uint64_t RootDirectory() const override;

    std::string ObjectName() const override;

    HANDLE_ATTRIBUTES Attributes() const override;

    bool isInheritable() const override;

    SECURITY_DESCRIPTOR* SecurityDescriptor() override;

    const SECURITY_DESCRIPTOR* SecurityDescriptor() const override;

    SECURITY_QUALITY_OF_SERVICE* SecurityQualityOfService() override;

    const SECURITY_QUALITY_OF_SERVICE* SecurityQualityOfService() const override;

    const std::string& FullPath(const KPCR& kpcr) const override;

    void Length(uint32_t Length = 0xFFFFFFFF) override;

    void RootDirectory(uint64_t RootDirectory) override;

    void ObjectName(const std::string& ObjectName) override;

    void ObjectNamePtr(const GuestVirtualAddress& pUnicodeString) override;

    void Attributes(HANDLE_ATTRIBUTES Attributes) override;

    void Inheritable(bool Inheritable) override;

    void SecurityQualityOfServicePtr(uint64_t pSecurityQualityOfService) override;

    GuestVirtualAddress address() const override;

    void write(std::ostream& os, const std::string& linePrefix = "") const override;

    Json::Value json() const override;

    OBJECT_ATTRIBUTES_IMPL(const GuestVirtualAddress& gva);

  private:
    void generateFullPathForKey(std::shared_ptr<const OBJECT>& object) const;
    void generateFullPathForFile(std::shared_ptr<const OBJECT>& object) const;

  private:
    const GuestVirtualAddress gva_;
    guest_ptr<structs::_OBJECT_ATTRIBUTES<PtrType>> header_;
    mutable std::optional<UNICODE_STRING_IMPL<PtrType>> ObjectName_;
    std::optional<SECURITY_DESCRIPTOR_IMPL<PtrType>> SecurityDescriptor_;
    std::optional<SECURITY_QUALITY_OF_SERVICE_IMPL> SecurityQualityOfService_;
    mutable std::string full_path_;
};

} // namespace nt
} // namespace windows
} // namespace introvirt