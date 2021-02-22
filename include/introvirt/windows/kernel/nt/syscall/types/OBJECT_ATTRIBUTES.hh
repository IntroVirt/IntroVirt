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

#include "SECURITY_DESCRIPTOR.hh"
#include "SECURITY_QUALITY_OF_SERVICE.hh"

#include <introvirt/core/fwd.hh>
#include <introvirt/core/injection/GuestAllocation.hh>
#include <introvirt/util/json/json.hh>
#include <introvirt/windows/kernel/nt/const/HANDLE_ATTRIBUTES.hh>
#include <introvirt/windows/kernel/nt/fwd.hh>

#include <cstdint>
#include <string>
#include <string_view>

namespace introvirt {
namespace windows {
namespace nt {

/**
 * The OBJECT_ATTRIBUTES structure is used as a parameter in many Windows system calls.
 */
class OBJECT_ATTRIBUTES {
  public:
    enum Attribute {
        OBJ_INHERIT = 0x00000002,
        OBJ_PERMANENT = 0x00000010,
        OBJ_EXCLUSIVE = 0x00000020,
        OBJ_CASE_INSENSITIVE = 0x00000040,
        OBJ_OPENIF = 0x00000080,
        OBJ_OPENLINK = 0x00000100,
        OBJ_KERNEL_HANDLE = 0x00000200,
        OBJ_FORCE_ACCESS_CHECK = 0x00000400,
        OBJ_VALID_ATTRIBUTES = 0x000007f2
    };

  public:
    virtual uint32_t Length() const = 0;

    /**
     * @returns The RootDirectory handle of the OBJECT_ATTRIBUTES
     */
    virtual uint64_t RootDirectory() const = 0;

    /**
     * @returns The ObjectName from the OBJECT_ATTRIBUTES, or NULL if one doesn't exist
     */
    virtual std::string ObjectName() const = 0;

    virtual HANDLE_ATTRIBUTES Attributes() const = 0;

    /**
     * @returns True if the object is inheritable to child processes
     */
    virtual bool isInheritable() const = 0;

    virtual SECURITY_DESCRIPTOR* SecurityDescriptor() = 0;

    virtual const SECURITY_DESCRIPTOR* SecurityDescriptor() const = 0;

    virtual SECURITY_QUALITY_OF_SERVICE* SecurityQualityOfService() = 0;

    virtual const SECURITY_QUALITY_OF_SERVICE* SecurityQualityOfService() const = 0;

    /**
     * @returns The root directory's name plus the ObjectName
     */
    virtual const std::string& FullPath(const KPCR& kpcr) const = 0;

    /*
     * @param Length The value to  in the Length field, or 0xFFFFFFFF to use the correct value
     */
    virtual void Length(uint32_t Length = 0xFFFFFFFF) = 0;

    virtual void RootDirectory(uint64_t RootDirectory) = 0;

    virtual void ObjectName(const std::string& ObjectName) = 0;

    /**
     *  the ObjectName pointer to a new address
     *
     * @param pUnicodeString The address to
     */
    virtual void ObjectNamePtr(const GuestVirtualAddress& pUnicodeString) = 0;

    virtual void Attributes(HANDLE_ATTRIBUTES Attributes) = 0;

    virtual void Inheritable(bool Inheritable) = 0;

    virtual void SecurityQualityOfServicePtr(uint64_t pSecurityQualityOfService) = 0;

    virtual GuestVirtualAddress address() const = 0;

    virtual void write(std::ostream& os, const std::string& linePrefix = "") const = 0;

    virtual Json::Value json() const = 0;

    static std::unique_ptr<OBJECT_ATTRIBUTES> make_unique(const NtKernel& kernel,
                                                          const GuestVirtualAddress& gva);

    virtual ~OBJECT_ATTRIBUTES() = default;
};

} /* namespace nt */
} /* namespace windows */

namespace inject {

template <>
class GuestAllocation<windows::nt::OBJECT_ATTRIBUTES>
    : public GuestAllocationComplexBase<windows::nt::OBJECT_ATTRIBUTES> {
  public:
    explicit GuestAllocation();

  private:
    std::optional<GuestAllocation<uint8_t[]>> buffer_;
};

} // namespace inject
} // namespace introvirt