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

#include <memory>
#include <ostream>
#include <string>

namespace introvirt {
namespace windows {
namespace nt {

class INITIAL_TEB {
  public:
    virtual uint64_t StackBase() const = 0;
    virtual void StackBase(uint64_t StackBase) = 0;

    virtual uint64_t StackLimit() const = 0;
    virtual void StackLimit(uint64_t StackLimit) = 0;

    virtual uint64_t StackCommit() const = 0;
    virtual void StackCommit(uint64_t StackCommit) = 0;

    virtual uint64_t StackCommitMax() const = 0;
    virtual void StackCommitMax(uint64_t StackCommitMax) = 0;

    virtual uint64_t StackReserved() const = 0;
    virtual void StackReserved(uint64_t StackReserved) = 0;

    virtual GuestVirtualAddress address() const = 0;

    virtual void write(std::ostream& os, const std::string& linePrefix = "") const = 0;
    virtual Json::Value json() const = 0;

    static std::unique_ptr<INITIAL_TEB> make_unique(const NtKernel& kernel,
                                                    const GuestVirtualAddress& gva);

    virtual ~INITIAL_TEB() = default;
};

} // namespace nt
} // namespace windows
} // namespace introvirt
