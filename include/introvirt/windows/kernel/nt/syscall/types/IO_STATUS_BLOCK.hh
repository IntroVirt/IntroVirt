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

#include <introvirt/core/fwd.hh>
#include <introvirt/core/injection/GuestAllocation.hh>
#include <introvirt/core/memory/GuestVirtualAddress.hh>
#include <introvirt/util/json/json.hh>
#include <introvirt/windows/kernel/nt/fwd.hh>

#include <cstdint>
#include <memory>

namespace introvirt {
namespace windows {
namespace nt {

class IO_STATUS_BLOCK {
  public:
    /**
     * Note: Status and Pointer refer to the same area of memory!
     *
     * @returns The Status field from the IO_STATUS_BLOCK
     */
    virtual uint64_t Status() const = 0;
    /**
     * Note: Status and Pointer refer to the same area of memory!
     *
     * @returns The Pointer field from the IO_STATUS_BLOCK
     */
    virtual uint64_t Pointer() const = 0;

    /**
     * @returns The Information field from the IO_STATUS_BLOCK
     */
    virtual uint64_t Information() const = 0;

    /**
     * Set the Status field in the IO_STATUS_BLOCK
     * Note: Status and Pointer refer to the same area of memory!
     *
     * @param Status The value to set
     */
    virtual void Status(uint64_t Status) = 0;

    /**
     * Set the Pointer field in the IO_STATUS_BLOCK
     * Note: Status and Pointer refer to the same area of memory!
     *
     * @param Pointer The value to set
     */
    virtual void Pointer(uint64_t Pointer) = 0;

    /**
     * Set the Information field in the IO_STATUS_BLOCK
     *
     * @param Information The value to set
     */
    virtual void Information(uint64_t Information) = 0;

    /**
     * @returns The virtual address of the structure
     */
    virtual GuestVirtualAddress address() const = 0;

    virtual void write(std::ostream& os, const std::string& linePrefix = "") const = 0;
    virtual Json::Value json() const = 0;

    static std::unique_ptr<IO_STATUS_BLOCK> make_unique(const NtKernel& kernel,
                                                        const GuestVirtualAddress& gva);

    virtual ~IO_STATUS_BLOCK() = default;
};

} /* namespace nt */
} /* namespace windows */

namespace inject {

template <>
class GuestAllocation<windows::nt::IO_STATUS_BLOCK>
    : public GuestAllocationComplexBase<windows::nt::IO_STATUS_BLOCK> {
  public:
    explicit GuestAllocation();

  private:
    std::optional<GuestAllocation<uint8_t[]>> buffer_;
};

} // namespace inject

} /* namespace introvirt */
