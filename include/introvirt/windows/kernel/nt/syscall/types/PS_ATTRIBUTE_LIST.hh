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

#include <introvirt/core/memory/GuestVirtualAddress.hh>
#include <introvirt/util/json/json.hh>
#include <introvirt/windows/kernel/nt/fwd.hh>
#include <introvirt/windows/kernel/nt/syscall/types/array_iterator.hh>

#include <cstdint>
#include <memory>

namespace introvirt {
namespace windows {
namespace nt {

enum PS_ATTRIBUTE_NUM {
    PsAttributeParentProcess,     // in HANDLE
    PsAttributeDebugPort,         // in HANDLE
    PsAttributeToken,             // in HANDLE
    PsAttributeClientId,          // out PCLIENT_ID
    PsAttributeTebAddress,        // out PTEB *
    PsAttributeImageName,         // in PWSTR
    PsAttributeImageInfo,         // out PSECTION_IMAGE_INFORMATION
    PsAttributeMemoryReserve,     // in PPS_MEMORY_RESERVE
    PsAttributePriorityClass,     // in UCHAR
    PsAttributeErrorMode,         // in ULONG
    PsAttributeStdHandleInfo,     // 10, in PPS_STD_HANDLE_INFO
    PsAttributeHandleList,        // in PHANDLE
    PsAttributeGroupAffinity,     // in PGROUP_AFFINITY
    PsAttributePreferredNode,     // in PUSHORT
    PsAttributeIdealProcessor,    // in PPROCESSOR_NUMBER
    PsAttributeUmsThread,         // ? in PUMS_CREATE_THREAD_ATTRIBUTES
    PsAttributeMitigationOptions, // in UCHAR
    PsAttributeProtectionLevel,
    PsAttributeSecurityCapabilities,
    PsAttributeJobList,
    PsAttributeChildProcessPolicy,
    PsAttributeAllApplicationPackagesPolicy,
    PsAttributeWin32kFilter,
    PsAttributeSafeOpenPromptOriginClaim,
    PsAttributeBnoIsolation,
    PsAttributeDesktopAppPolicy,
    PsAttributeChpe,
    PsAttributeMax
};

class PS_ATTRIBUTE {
  public:
    // The attribute number
    virtual PS_ATTRIBUTE_NUM AttributeNumber() const = 0;
    virtual void AttributeNumber(PS_ATTRIBUTE_NUM num) = 0;

    virtual uint32_t AttributeFlags() const = 0;
    virtual void AttributeFlags(uint32_t flags) = 0;

    virtual uint64_t Size() const = 0;
    virtual void Size(uint64_t size) = 0;

    virtual uint64_t Value() const = 0;
    virtual void Value(uint64_t value) = 0;

    virtual uint64_t ReturnLength() const = 0;
    virtual void ReturnLength(uint64_t len) = 0;

    /*
     * A bit that indicates if the attribute is input-only
     */
    virtual bool AttributeInputOnly() const = 0;
    virtual void AttributeInputOnly(bool input) = 0;

    /*
     * A bit that indicates the attribute can be used with threads
     */
    virtual bool AttributeThreads() const = 0;
    virtual void AttributeThreads(bool threads) = 0;

    /**
     * @brief Get the address of this entry
     *
     * @return GuestVirtualAddress
     */
    virtual GuestVirtualAddress address() const = 0;

    /**
     * @brief Write out a human-readable representation
     *
     * @param os
     * @param linePrefix
     */
    virtual void write(std::ostream& os, const std::string& linePrefix = "") const = 0;

    /**
     * @brief Get a Json respresentation of the buffer
     *
     * @return Json::Value
     */
    virtual Json::Value json() const = 0;

    virtual ~PS_ATTRIBUTE() = default;
};

class PS_ATTRIBUTE_LIST {
  public:
    using iterator = array_iterator<PS_ATTRIBUTE, PS_ATTRIBUTE_LIST, false>;
    using const_iterator = array_iterator<PS_ATTRIBUTE, PS_ATTRIBUTE_LIST, true>;

    /**
     * @brief Get an entry at the specified index
     *
     * @param index The index into the array
     * @return PS_ATTRIBUTE&
     */
    virtual PS_ATTRIBUTE& operator[](uint32_t index) = 0;
    virtual const PS_ATTRIBUTE& operator[](uint32_t index) const = 0;

    /**
     * @copydoc PS_ATTRIBUTE_LIST::operator[](uint32_t)
     *
     * @param index
     * @return PS_ATTRIBUTE&
     */
    virtual PS_ATTRIBUTE& at(uint32_t index) = 0;
    virtual const PS_ATTRIBUTE& at(uint32_t index) const = 0;

    /**
     * @brief Remove an element from the list
     *
     * @param iter An iter to the element to remove
     * @return const_iterator containing the next element after the erased one
     */
    virtual iterator erase(const const_iterator& iter) = 0;

    /**
     * @brief Get the number of entries
     *
     * @return uint32_t
     */
    virtual uint32_t length() const = 0;

    /**
     * @brief Get an iterator to the first entry
     *
     * @return const_iterator
     */
    virtual iterator begin() = 0;

    /**
     * @brief Get the end iterator
     *
     * @return const_iterator
     */
    virtual iterator end() = 0;

    /**
     * @brief Get an iterator to the first entry
     *
     * @return const_iterator
     */
    virtual const_iterator begin() const = 0;

    /**
     * @brief Get the end iterator
     *
     * @return const_iterator
     */
    virtual const_iterator end() const = 0;

    /**
     * @brief Get the address of the buffer
     *
     * @return GuestVirtualAddress
     */
    virtual GuestVirtualAddress address() const = 0;

    /**
     * @brief Get the total size of the buffer in bytes
     *
     * This may not relate to the total number of entries;
     * the buffer could be larger than necessary, for example.
     *
     * @return uint32_t
     */
    virtual uint32_t buffer_size() const = 0;

    /**
     * @brief Write out a human-readable representation
     *
     * @param os
     * @param linePrefix
     */
    virtual void write(std::ostream& os, const std::string& linePrefix = "") const = 0;

    /**
     * @brief Get a Json respresentation of the buffer
     *
     * @return Json::Value
     */
    virtual Json::Value json() const = 0;

    static std::unique_ptr<PS_ATTRIBUTE_LIST> make_unique(const NtKernel& kernel,
                                                          const GuestVirtualAddress& gva);

    virtual ~PS_ATTRIBUTE_LIST() = default;
};

const std::string& to_string(PS_ATTRIBUTE_NUM attribute);
std::ostream& operator<<(std::ostream&, PS_ATTRIBUTE_NUM);

} /* namespace nt */
} /* namespace windows */
} /* namespace introvirt */
