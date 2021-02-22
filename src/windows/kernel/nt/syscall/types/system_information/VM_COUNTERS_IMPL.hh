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

template <typename PtrType>
struct _VM_COUNTERS {
    PtrType PeakVirtualSize;
    PtrType VirtualSize;
    uint32_t PageFaultCount;
    PtrType PeakWorkingSetSize;
    PtrType WorkingSetSize;
    PtrType QuotaPeakPagedPoolUsage;
    PtrType QuotaPagedPoolUsage;
    PtrType QuotaPeakNonPagedPoolUsage;
    PtrType QuotaNonPagedPoolUsage;
    PtrType PagefileUsage;
    PtrType PeakPagefileUsage;
    PtrType PrivatePageCount;
};

} // namespace structs

template <typename PtrType>
class VM_COUNTERS_IMPL final : public VM_COUNTERS {
  public:
    uint64_t PeakVirtualSize() const override { return this->data_->PeakVirtualSize; }
    void PeakVirtualSize(uint64_t PeakVirtualSize) override {
        this->data_->PeakVirtualSize = PeakVirtualSize;
    }

    uint64_t VirtualSize() const override { return this->data_->VirtualSize; }
    void VirtualSize(uint64_t VirtualSize) override { this->data_->VirtualSize = VirtualSize; }

    uint32_t PageFaultCount() const override { return this->data_->PageFaultCount; }
    void PageFaultCount(uint32_t PageFaultCount) override {
        this->data_->PageFaultCount = PageFaultCount;
    }

    uint64_t PeakWorkingSetSize() const override { return this->data_->PeakWorkingSetSize; }
    void PeakWorkingSetSize(uint64_t PeakWorkingSetSize) override {
        this->data_->PeakWorkingSetSize = PeakWorkingSetSize;
    }

    uint64_t WorkingSetSize() const override { return this->data_->WorkingSetSize; }
    void WorkingSetSize(uint64_t WorkingSetSize) override {
        this->data_->WorkingSetSize = WorkingSetSize;
    }

    uint64_t QuotaPeakPagedPoolUsage() const override {
        return this->data_->QuotaPeakPagedPoolUsage;
    }
    void QuotaPeakPagedPoolUsage(uint64_t QuotaPeakPagedPoolUsage) override {
        this->data_->QuotaPeakPagedPoolUsage = QuotaPeakPagedPoolUsage;
    }

    uint64_t QuotaPagedPoolUsage() const override { return this->data_->QuotaPagedPoolUsage; }
    void QuotaPagedPoolUsage(uint64_t QuotaPagedPoolUsage) override {
        this->data_->QuotaPagedPoolUsage = QuotaPagedPoolUsage;
    }

    uint64_t QuotaPeakNonPagedPoolUsage() const override {
        return this->data_->QuotaPeakNonPagedPoolUsage;
    }
    void QuotaPeakNonPagedPoolUsage(uint64_t QuotaPeakNonPagedPoolUsage) override {
        this->data_->QuotaPeakNonPagedPoolUsage = QuotaPeakNonPagedPoolUsage;
    }

    uint64_t QuotaNonPagedPoolUsage() const override { return this->data_->QuotaNonPagedPoolUsage; }
    void QuotaNonPagedPoolUsage(uint64_t QuotaNonPagedPoolUsage) override {
        this->data_->QuotaNonPagedPoolUsage = QuotaNonPagedPoolUsage;
    }

    uint64_t PagefileUsage() const override { return this->data_->PagefileUsage; }
    void PagefileUsage(uint64_t PagefileUsage) override {
        this->data_->PagefileUsage = PagefileUsage;
    }

    uint64_t PeakPagefileUsage() const override { return this->data_->PeakPagefileUsage; }
    void PeakPagefileUsage(uint64_t PeakPagefileUsage) override {
        this->data_->PeakPagefileUsage = PeakPagefileUsage;
    }

    uint64_t PrivatePageCount() const override { return this->data_->PrivatePageCount; }
    void PrivatePageCount(uint64_t PrivatePageCount) override {
        this->data_->PrivatePageCount = PrivatePageCount;
    }

    virtual void write(std::ostream& os, const std::string& linePrefix = "") const override {
        boost::io::ios_flags_saver ifs(os);
        os << std::dec;
        os << linePrefix << "PeakVirtualSize: " << PeakVirtualSize() << '\n';
        os << linePrefix << "VirtualSize: " << VirtualSize() << '\n';
        os << linePrefix << "PageFaultCount: " << PageFaultCount() << '\n';
        os << linePrefix << "PeakWorkingSetSize: " << PeakWorkingSetSize() << '\n';
        os << linePrefix << "WorkingSetSize: " << WorkingSetSize() << '\n';
        os << linePrefix << "QuotaPeakPagedPoolUsage: " << QuotaPeakPagedPoolUsage() << '\n';
        os << linePrefix << "QuotaPagedPoolUsage: " << QuotaPagedPoolUsage() << '\n';
        os << linePrefix << "QuotaPeakNonPagedPoolUsage: " << QuotaPeakNonPagedPoolUsage() << '\n';
        os << linePrefix << "QuotaNonPagedPoolUsage: " << QuotaNonPagedPoolUsage() << '\n';
        os << linePrefix << "PagefileUsage: " << PagefileUsage() << '\n';
        os << linePrefix << "PeakPagefileUsage: " << PeakPagefileUsage() << '\n';
        os << linePrefix << "PrivatePageCount: " << PrivatePageCount() << '\n';
    }

    virtual Json::Value json() const override {
        Json::Value result;
        result["PeakVirtualSize"] = PeakVirtualSize();
        result["VirtualSize"] = VirtualSize();
        result["PageFaultCount"] = PageFaultCount();
        result["PeakWorkingSetSize"] = PeakWorkingSetSize();
        result["WorkingSetSize"] = WorkingSetSize();
        result["QuotaPeakPagedPoolUsage"] = QuotaPeakPagedPoolUsage();
        result["QuotaPagedPoolUsage"] = QuotaPagedPoolUsage();
        result["QuotaPeakNonPagedPoolUsage"] = QuotaPeakNonPagedPoolUsage();
        result["QuotaNonPagedPoolUsage"] = QuotaNonPagedPoolUsage();
        result["PagefileUsage"] = PagefileUsage();
        result["PeakPagefileUsage"] = PeakPagefileUsage();
        result["PrivatePageCount"] = PrivatePageCount();
        return result;
    }

    GuestVirtualAddress address() const override { return gva_; }

    VM_COUNTERS_IMPL(const GuestVirtualAddress& gva) : gva_(gva), data_(gva_) {}

  private:
    const GuestVirtualAddress gva_;
    guest_ptr<structs::_VM_COUNTERS<PtrType>> data_;
};

} // namespace nt
} // namespace windows
} // namespace introvirt
