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
    uint64_t PeakVirtualSize() const override { return this->ptr_->PeakVirtualSize; }
    void PeakVirtualSize(uint64_t PeakVirtualSize) override {
        this->ptr_->PeakVirtualSize = PeakVirtualSize;
    }

    uint64_t VirtualSize() const override { return this->ptr_->VirtualSize; }
    void VirtualSize(uint64_t VirtualSize) override { this->ptr_->VirtualSize = VirtualSize; }

    uint32_t PageFaultCount() const override { return this->ptr_->PageFaultCount; }
    void PageFaultCount(uint32_t PageFaultCount) override {
        this->ptr_->PageFaultCount = PageFaultCount;
    }

    uint64_t PeakWorkingSetSize() const override { return this->ptr_->PeakWorkingSetSize; }
    void PeakWorkingSetSize(uint64_t PeakWorkingSetSize) override {
        this->ptr_->PeakWorkingSetSize = PeakWorkingSetSize;
    }

    uint64_t WorkingSetSize() const override { return this->ptr_->WorkingSetSize; }
    void WorkingSetSize(uint64_t WorkingSetSize) override {
        this->ptr_->WorkingSetSize = WorkingSetSize;
    }

    uint64_t QuotaPeakPagedPoolUsage() const override {
        return this->ptr_->QuotaPeakPagedPoolUsage;
    }
    void QuotaPeakPagedPoolUsage(uint64_t QuotaPeakPagedPoolUsage) override {
        this->ptr_->QuotaPeakPagedPoolUsage = QuotaPeakPagedPoolUsage;
    }

    uint64_t QuotaPagedPoolUsage() const override { return this->ptr_->QuotaPagedPoolUsage; }
    void QuotaPagedPoolUsage(uint64_t QuotaPagedPoolUsage) override {
        this->ptr_->QuotaPagedPoolUsage = QuotaPagedPoolUsage;
    }

    uint64_t QuotaPeakNonPagedPoolUsage() const override {
        return this->ptr_->QuotaPeakNonPagedPoolUsage;
    }
    void QuotaPeakNonPagedPoolUsage(uint64_t QuotaPeakNonPagedPoolUsage) override {
        this->ptr_->QuotaPeakNonPagedPoolUsage = QuotaPeakNonPagedPoolUsage;
    }

    uint64_t QuotaNonPagedPoolUsage() const override { return this->ptr_->QuotaNonPagedPoolUsage; }
    void QuotaNonPagedPoolUsage(uint64_t QuotaNonPagedPoolUsage) override {
        this->ptr_->QuotaNonPagedPoolUsage = QuotaNonPagedPoolUsage;
    }

    uint64_t PagefileUsage() const override { return this->ptr_->PagefileUsage; }
    void PagefileUsage(uint64_t PagefileUsage) override {
        this->ptr_->PagefileUsage = PagefileUsage;
    }

    uint64_t PeakPagefileUsage() const override { return this->ptr_->PeakPagefileUsage; }
    void PeakPagefileUsage(uint64_t PeakPagefileUsage) override {
        this->ptr_->PeakPagefileUsage = PeakPagefileUsage;
    }

    uint64_t PrivatePageCount() const override { return this->ptr_->PrivatePageCount; }
    void PrivatePageCount(uint64_t PrivatePageCount) override {
        this->ptr_->PrivatePageCount = PrivatePageCount;
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

    guest_ptr<void> ptr() const override { return ptr_; }

    VM_COUNTERS_IMPL(const guest_ptr<void>& ptr) : ptr_(ptr) {}

  private:
    guest_ptr<structs::_VM_COUNTERS<PtrType>> ptr_;
};

} // namespace nt
} // namespace windows
} // namespace introvirt
