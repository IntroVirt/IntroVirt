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
#include <introvirt/windows/kernel/nt/syscall/types/system_information/SYSTEM_PROCESS_INFORMATION.hh>

#include <boost/io/ios_state.hpp>

namespace introvirt {
namespace windows {
namespace nt {

namespace structs {

struct _IO_COUNTERS {
    uint64_t ReadOperationCount;
    uint64_t WriteOperationCount;
    uint64_t OtherOperationCount;
    uint64_t ReadTransferCount;
    uint64_t WriteTransferCount;
    uint64_t OtherTransferCount;
};

} // namespace structs

class IO_COUNTERS_IMPL final : public IO_COUNTERS {
  public:
    uint64_t ReadOperationCount() const override { return data_->ReadOperationCount; }
    void ReadOperationCount(uint64_t value) override { data_->ReadOperationCount = value; }

    uint64_t WriteOperationCount() const override { return data_->WriteOperationCount; }
    void WriteOperationCount(uint64_t value) override { data_->WriteOperationCount = value; }

    uint64_t OtherOperationCount() const override { return data_->OtherOperationCount; }
    void OtherOperationCount(uint64_t value) override { data_->OtherOperationCount = value; }

    uint64_t ReadTransferCount() const override { return data_->ReadTransferCount; }
    void ReadTransferCount(uint64_t value) override { data_->ReadTransferCount = value; }

    uint64_t WriteTransferCount() const override { return data_->WriteTransferCount; }
    void WriteTransferCount(uint64_t value) override { data_->WriteTransferCount = value; }

    uint64_t OtherTransferCount() const override { return data_->OtherTransferCount; }
    void OtherTransferCount(uint64_t value) override { data_->OtherTransferCount = value; }

    virtual void write(std::ostream& os, const std::string& linePrefix = "") const override {
        boost::io::ios_flags_saver ifs(os);
        os << std::dec;
        os << linePrefix << "ReadOperationCount: " << ReadOperationCount() << '\n';
        os << linePrefix << "WriteOperationCount: " << WriteOperationCount() << '\n';
        os << linePrefix << "OtherOperationCount: " << OtherOperationCount() << '\n';
        os << linePrefix << "ReadTransferCount: " << ReadTransferCount() << '\n';
        os << linePrefix << "WriteTransferCount: " << WriteTransferCount() << '\n';
        os << linePrefix << "OtherTransferCount: " << OtherTransferCount() << '\n';
    }

    virtual Json::Value json() const override {
        Json::Value result;
        result["ReadOperationCount"] = ReadOperationCount();
        result["WriteOperationCount"] = WriteOperationCount();
        result["OtherOperationCount"] = OtherOperationCount();
        result["ReadTransferCount"] = ReadTransferCount();
        result["WriteTransferCount"] = WriteTransferCount();
        result["OtherTransferCount"] = OtherTransferCount();
        return result;
    }

    GuestVirtualAddress address() const override { return gva_; }

    IO_COUNTERS_IMPL(const GuestVirtualAddress& gva) : gva_(gva), data_(gva_) {}

  private:
    const GuestVirtualAddress gva_;
    guest_ptr<structs::_IO_COUNTERS> data_;
};

} // namespace nt
} // namespace windows
} // namespace introvirt