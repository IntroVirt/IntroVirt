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

#include <cstdint>
#include <memory>

namespace introvirt {
namespace windows {
namespace nt {

class PORT_MESSAGE {
  public:
    /**
     * @returns The length of just the data
     */
    virtual int16_t DataLength() const = 0;

    /**
     * @returns The size of the LPC_MESSAGE structure + the data length
     */
    virtual int16_t TotalLength() const = 0;

    virtual LPC_TYPE MessageType() const = 0;

    virtual int16_t DataInfoOffset() const = 0;

    virtual const CLIENT_ID& ClientId() const = 0;

    virtual uint32_t MessageId() const = 0;

    virtual uint32_t CallbackId() const = 0;

    virtual GuestVirtualAddress address() const = 0;

    // The size of the LPC_MESSAGE header
    virtual uint64_t HeaderSize() const = 0;

    virtual void write(std::ostream& os, const std::string& linePrefix = "") const = 0;

    virtual Json::Value json() const = 0;

    static std::unique_ptr<PORT_MESSAGE> make_unique(const NtKernel& kernel,
                                                     const GuestVirtualAddress& gva);

    virtual ~PORT_MESSAGE() = default;
};

} /* namespace nt */
} /* namespace windows */
} /* namespace introvirt */
