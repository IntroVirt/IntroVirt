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

#include <introvirt/core/injection/GuestAllocation.hh>
#include <introvirt/core/memory/GuestVirtualAddress.hh>
#include <introvirt/windows/common/Utf16String.hh>

#include <introvirt/core/fwd.hh>
#include <introvirt/windows/fwd.hh>

#include <locale>
#include <memory>
#include <string>

namespace introvirt {
namespace windows {
namespace nt {

/**
 * @brief Class for the Windows UNICODE_STRING structure.
 *
 */
class UNICODE_STRING : public Utf16String {
  public:
    /**
     * @returns The length of the string, in bytes
     */
    uint16_t Length() const override = 0;

    /**
     * @brief Change the value of the Length field
     */
    virtual void Length(uint16_t length) = 0;

    /*
     * @returns The maximum length of the string, in bytes
     */
    virtual uint16_t MaximumLength() const = 0;
    virtual void MaximumLength(uint16_t MaximumLength) = 0;

    virtual GuestVirtualAddress BufferAddress() const = 0;
    virtual void BufferAddress(const GuestVirtualAddress& gva) = 0;

    Json::Value json() const override = 0;

    virtual GuestVirtualAddress address() const = 0;

    static std::unique_ptr<UNICODE_STRING> make_unique(const NtKernel& kernel,
                                                       const GuestVirtualAddress& gva);

    ~UNICODE_STRING() override = default;
};

} /* namespace nt */
} /* namespace windows */

namespace inject {

template <>
class GuestAllocation<windows::nt::UNICODE_STRING>
    : public GuestAllocationComplexBase<windows::nt::UNICODE_STRING> {
  public:
    explicit GuestAllocation(const std::string& value);
    explicit GuestAllocation(const std::string& value, unsigned int MaximumLength);

  private:
    std::optional<GuestAllocation<uint8_t[]>> buffer_;
};

} /* namespace inject */
} /* namespace introvirt */
