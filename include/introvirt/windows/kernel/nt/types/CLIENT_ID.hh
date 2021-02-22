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
#include <introvirt/util/json/json.hh>
#include <introvirt/windows/kernel/nt/fwd.hh>

#include <cstdint>
#include <memory>
#include <ostream>

namespace introvirt {
namespace windows {
namespace nt {

/**
 * @brief Class for handling the Windows NT CLIENT_ID structure.
 *
 * This structure holds two fields, indicating both process and
 * thread identifiers.
 */
class CLIENT_ID {
  public:
    virtual uint64_t UniqueProcess() const = 0;
    virtual uint64_t UniqueThread() const = 0;

    virtual void UniqueProcess(uint64_t UniqueProcess) = 0;
    virtual void UniqueThread(uint64_t UniqueThread) = 0;

    virtual void write(std::ostream& os, const std::string& linePrefix = "") const = 0;

    virtual Json::Value json() const = 0;
    virtual operator Json::Value() const = 0;

    virtual GuestVirtualAddress address() const = 0;

    static std::unique_ptr<CLIENT_ID> make_unique(const NtKernel& kernel,
                                                  const GuestVirtualAddress& gva);

    virtual ~CLIENT_ID() = default;
};

std::ostream& operator<<(std::ostream& os, const CLIENT_ID& cid);

} /* namespace nt */
} /* namespace windows */

namespace inject {

template <>
class GuestAllocation<windows::nt::CLIENT_ID>
    : public GuestAllocationComplexBase<windows::nt::CLIENT_ID> {
  public:
    explicit GuestAllocation();
    explicit GuestAllocation(uint64_t UniqueProcess, uint64_t UniqueThread);

  private:
    std::optional<GuestAllocation<uint8_t[]>> buffer_;
};

} // namespace inject

} /* namespace introvirt */
