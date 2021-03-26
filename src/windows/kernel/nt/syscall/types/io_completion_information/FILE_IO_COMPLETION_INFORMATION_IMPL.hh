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

#include "windows/kernel/nt/syscall/types/IO_STATUS_BLOCK_IMPL.hh"

#include <introvirt/core/memory/guest_ptr.hh>
#include <introvirt/windows/kernel/nt/syscall/types/io_completion_information/FILE_IO_COMPLETION_INFORMATION.hh>

namespace introvirt {
namespace windows {
namespace nt {

namespace structs {

template <typename PtrType>
struct _FILE_IO_COMPLETION_INFORMATION {
    PtrType KeyContext;
    PtrType ApcContext;
    _IO_STATUS_BLOCK<PtrType> IoStatusBlock;
} __attribute__((__packed__));

} // namespace structs

template <typename PtrType>
class FILE_IO_COMPLETION_INFORMATION_IMPL final : public FILE_IO_COMPLETION_INFORMATION {
    using _FILE_IO_COMPLETION_INFORMATION = structs::_FILE_IO_COMPLETION_INFORMATION<PtrType>;

  public:
    uint64_t KeyContextPtr() const override { return ptr_->KeyContext; }
    void KeyContextPtr(uint64_t value) override { ptr_->KeyContext = value; }

    uint64_t ApcContextPtr() const override { return ptr_->ApcContext; }
    void ApcContextPtr(uint64_t value) override { ptr_->ApcContext = value; }

    const IO_STATUS_BLOCK* IoStatusBlock() const override;
    IO_STATUS_BLOCK* IoStatusBlock() override;

    void write(std::ostream& os, const std::string& linePrefix = "") const override;
    Json::Value json() const override;

    guest_ptr<void> ptr() const override { return ptr_; }

    FILE_IO_COMPLETION_INFORMATION_IMPL(const guest_ptr<void>& ptr)
        : ptr_(ptr),
          io_status_block_(ptr + offsetof(_FILE_IO_COMPLETION_INFORMATION, IoStatusBlock)) {}

  private:
    guest_ptr<_FILE_IO_COMPLETION_INFORMATION> ptr_;
    IO_STATUS_BLOCK_IMPL<PtrType> io_status_block_;
};

} // namespace nt
} // namespace windows
} // namespace introvirt
