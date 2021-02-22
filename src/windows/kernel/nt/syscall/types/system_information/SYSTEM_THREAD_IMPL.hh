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
struct _SYSTEM_THREAD {
    int64_t KernelTime;
    int64_t UserTime;
    int64_t CreateTime;
    uint32_t WaitTime;
    PtrType StartAddress;
    PtrType UniqueProcessId;
    PtrType UniqueThreadId;
    uint32_t Priority;
    int32_t BasePriority;
    uint32_t ContextSwitchCount;
    uint32_t State;      // KTHREAD_STATE enum
    uint32_t WaitReason; // KWAIT_REASON enum
};

} // namespace structs

template <typename PtrType>
class SYSTEM_THREAD_IMPL final : public SYSTEM_THREAD {
  public:
    int64_t KernelTime() const override { return this->data_->KernelTime; }
    void KernelTime(int64_t KernelTime) override { this->data_->KernelTime = KernelTime; }

    int64_t UserTime() const override { return this->data_->UserTime; }
    void UserTime(int64_t UserTime) override { this->data_->UserTime = UserTime; }

    int64_t CreateTime() const override { return this->data_->CreateTime; }
    void CreateTime(int64_t CreateTime) override { this->data_->CreateTime = CreateTime; }

    uint32_t WaitTime() const override { return this->data_->WaitTime; }
    void WaitTime(uint32_t WaitTime) override { this->data_->WaitTime = WaitTime; }

    uint64_t StartAddress() const override { return this->data_->StartAddress; }
    void StartAddress(uint64_t StartAddress) override { this->data_->StartAddress = StartAddress; }

    uint64_t UniqueProcessId() const override { return this->data_->UniqueProcessId; }
    void UniqueProcessId(uint64_t UniqueProcessId) override {
        this->data_->UniqueProcessId = UniqueProcessId;
    }

    uint64_t UniqueThreadId() const override { return this->data_->UniqueThreadId; }
    void UniqueThreadId(uint64_t UniqueThreadId) override {
        this->data_->UniqueThreadId = UniqueThreadId;
    }

    uint32_t Priority() const override { return this->data_->Priority; }
    void Priority(uint32_t Priority) override { this->data_->Priority = Priority; }

    int32_t BasePriority() const override { return this->data_->BasePriority; }
    void BasePriority(int32_t BasePriority) override { this->data_->BasePriority = BasePriority; }

    uint32_t ContextSwitchCount() const override { return this->data_->ContextSwitchCount; }
    void ContextSwitchCount(uint32_t ContextSwitchCount) override {
        this->data_->ContextSwitchCount = ContextSwitchCount;
    }

    KTHREAD_STATE State() const override { return static_cast<KTHREAD_STATE>(this->data_->State); }
    void State(KTHREAD_STATE State) override { this->data_->State = State; }

    KWAIT_REASON WaitReason() const override {
        return static_cast<KWAIT_REASON>(this->data_->WaitReason);
    }
    void WaitReason(KWAIT_REASON WaitReason) override { this->data_->WaitReason = WaitReason; }

    void write(std::ostream& os, const std::string& linePrefix = "") const override {
        boost::io::ios_flags_saver ifs(os);
        os << std::dec;
        os << linePrefix << "UniqueThreadId: " << UniqueThreadId() << '\n';
        os << linePrefix << "  UniqueProcessId: " << UniqueProcessId() << '\n';
        os << linePrefix << "  KernelTime: " << KernelTime() << '\n';
        os << linePrefix << "  UserTime: " << UserTime() << '\n';
        os << linePrefix << "  CreateTime: " << CreateTime() << '\n';
        os << linePrefix << "  WaitTime: " << WaitTime() << '\n';
        os << linePrefix << "  StartAddress: 0x" << std::hex << StartAddress() << std::dec << '\n';
        os << linePrefix << "  Priority: " << Priority() << '\n';
        os << linePrefix << "  BasePriority: " << BasePriority() << '\n';
        os << linePrefix << "  ContextSwitchCount: " << ContextSwitchCount() << '\n';
        os << linePrefix << "  State: " << State() << '\n';
        os << linePrefix << "  WaitReason: " << WaitReason() << '\n';
    }

    Json::Value json() const override {
        Json::Value result;
        result["KernelTime"] = KernelTime();
        result["UserTime"] = UserTime();
        result["CreateTime"] = CreateTime();
        result["WaitTime"] = WaitTime();
        result["StartAddress"] = StartAddress();
        result["UniqueProcessId"] = UniqueProcessId();
        result["UniqueThreadId"] = UniqueThreadId();
        result["Priority"] = Priority();
        result["BasePriority"] = BasePriority();
        result["ContextSwitchCount"] = ContextSwitchCount();
        result["State"] = to_string(State());
        result["WaitReason"] = to_string(WaitReason());
        return result;
    }

    GuestVirtualAddress address() const override { return gva_; }

    SYSTEM_THREAD_IMPL(const GuestVirtualAddress& gva) : gva_(gva), data_(gva_) {}

  private:
    const GuestVirtualAddress gva_;
    guest_ptr<structs::_SYSTEM_THREAD<PtrType>> data_;
};

} // namespace nt
} // namespace windows
} // namespace introvirt
