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

#include <introvirt/core/memory/guest_ptr.hh>
#include <introvirt/windows/kernel/nt/syscall/types/IO_STATUS_BLOCK.hh>

namespace introvirt {
namespace windows {
namespace nt {

namespace structs {

template <typename PtrType>
struct _IO_STATUS_BLOCK {
    union {
        uint32_t Status;
        PtrType Pointer;
    };
    PtrType Information;
};

static_assert(offsetof(_IO_STATUS_BLOCK<uint32_t>, Information) == 0x4);
static_assert(offsetof(_IO_STATUS_BLOCK<uint64_t>, Information) == 0x8);
static_assert(sizeof(_IO_STATUS_BLOCK<uint32_t>) == 0x8);
static_assert(sizeof(_IO_STATUS_BLOCK<uint64_t>) == 0x10);

} // namespace structs

template <typename PtrType>
class IO_STATUS_BLOCK_IMPL final : public IO_STATUS_BLOCK {
  public:
    /**
     * Note: Status and Pointer refer to the same area of memory!
     *
     * @returns The Status field from the IO_STATUS_BLOCK
     */
    uint64_t Status() const override { return data_->Status; }

    /**
     * Note: Status and Pointer refer to the same area of memory!
     *
     * @returns The Pointer field from the IO_STATUS_BLOCK
     */
    uint64_t Pointer() const override { return data_->Pointer; }

    /**
     * @returns The Information field from the IO_STATUS_BLOCK
     */
    uint64_t Information() const override { return data_->Information; }

    /**
     * Set the Status field in the IO_STATUS_BLOCK
     * Note: Status and Pointer refer to the same area of memory!
     *
     * @param Status The value to set
     */
    void Status(uint64_t Status) override { data_->Status = Status; }

    /**
     * Set the Pointer field in the IO_STATUS_BLOCK
     * Note: Status and Pointer refer to the same area of memory!
     *
     * @param Pointer The value to set
     */
    void Pointer(uint64_t Pointer) override { data_->Pointer = Pointer; }

    /**
     * Set the Information field in the IO_STATUS_BLOCK
     *
     * @param Information The value to set
     */
    void Information(uint64_t Information) override { data_->Information = Information; }

    /**
     * @returns The  address of the structure
     */
    GuestVirtualAddress address() const override { return gva_; }

    void write(std::ostream& os, const std::string& linePrefix = "") const override;
    Json::Value json() const override;

    IO_STATUS_BLOCK_IMPL(const GuestVirtualAddress& gva) : gva_(gva), data_(gva_) {}

  private:
    GuestVirtualAddress gva_;
    guest_ptr<structs::_IO_STATUS_BLOCK<PtrType>> data_;
};

} // namespace nt
} // namespace windows
} // namespace introvirt