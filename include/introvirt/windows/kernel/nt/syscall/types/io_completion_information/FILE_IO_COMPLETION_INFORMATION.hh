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

#include <introvirt/windows/kernel/nt/syscall/types/IO_STATUS_BLOCK.hh>

#include <introvirt/util/json/json.hh>

#include <memory>

namespace introvirt {
namespace windows {
namespace nt {

class FILE_IO_COMPLETION_INFORMATION {
  public:
    virtual uint64_t KeyContextPtr() const = 0;
    virtual void KeyContextPtr(uint64_t value) = 0;

    virtual uint64_t ApcContextPtr() const = 0;
    virtual void ApcContextPtr(uint64_t value) = 0;

    virtual const IO_STATUS_BLOCK* IoStatusBlock() const = 0;
    virtual IO_STATUS_BLOCK* IoStatusBlock() = 0;

    virtual GuestVirtualAddress address() const = 0;

    virtual void write(std::ostream& os, const std::string& linePrefix = "") const = 0;
    virtual Json::Value json() const = 0;

    static std::unique_ptr<FILE_IO_COMPLETION_INFORMATION>
    make_unique(const NtKernel& kernel, const GuestVirtualAddress& gva);

    virtual ~FILE_IO_COMPLETION_INFORMATION() = default;
};

} // namespace nt
} // namespace windows
} // namespace introvirt
