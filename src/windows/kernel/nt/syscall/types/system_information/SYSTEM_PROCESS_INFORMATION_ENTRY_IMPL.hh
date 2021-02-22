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

#include "IO_COUNTERS_IMPL.hh"
#include "SYSTEM_THREAD_IMPL.hh"
#include "VM_COUNTERS_IMPL.hh"

#include "windows/kernel/nt/syscall/types/array_iterable.hh"
#include "windows/kernel/nt/types/UNICODE_STRING_IMPL.hh"

#include <introvirt/core/exception/BufferTooSmallException.hh>
#include <introvirt/windows/kernel/nt/syscall/types/system_information/SYSTEM_PROCESS_INFORMATION.hh>

#include <boost/io/ios_state.hpp>

namespace introvirt {
namespace windows {
namespace nt {

namespace structs {

template <typename PtrType>
struct _SYSTEM_PROCESS_INFORMATION {
    uint32_t NextEntryOffset;
    uint32_t NumberOfThreads;
    int64_t WorkingSetPrivateSize;
    uint32_t HardFaultCount;
    uint32_t NumberOfThreadsHighWatermark;
    int64_t CycleTime;
    int64_t CreateTime;
    int64_t UserTime;
    int64_t KernelTime;
    _UNICODE_STRING<PtrType> ImageName;
    int32_t BasePriority;
    PtrType UniqueProcessId;
    PtrType InheritedFromUniqueProcessId;
    uint32_t HandleCount;
    uint32_t SessionId;
    uint32_t UniqueProcessKey;
    _VM_COUNTERS<PtrType> VMCounters;
    _IO_COUNTERS IOCounters;
    _SYSTEM_THREAD<PtrType> Threads[];
};

} // namespace structs

template <typename PtrType>
using ThreadArrayImplBase =
    array_iterable<SYSTEM_THREAD_IMPL<PtrType>, SYSTEM_PROCESS_INFORMATION_ENTRY::ThreadArray,
                   sizeof(structs::_SYSTEM_THREAD<PtrType>)>;

template <typename PtrType>
class ThreadArrayImpl final : public ThreadArrayImplBase<PtrType> {
  public:
    uint32_t buffer_size() const override { return buffer_size_; }

    void write(std::ostream& os, const std::string& linePrefix = "") const override {
        boost::io::ios_flags_saver ifs(os);
        os << std::dec;
        for (auto& entry : *this) {
            entry.write(os, linePrefix);
        }
    }

    Json::Value json() const override {
        Json::Value result;
        for (auto& entry : *this) {
            result.append(entry.json());
        }
        return result;
    }

    ThreadArrayImpl(const GuestVirtualAddress pEntryCount, const GuestVirtualAddress& pFirstEntry,
                    uint32_t buffer_size)
        : ThreadArrayImplBase<PtrType>(pEntryCount, pFirstEntry), buffer_size_(buffer_size) {

        // TODO : Pass in buffer_size for bounds checking
    }

  private:
    const uint32_t buffer_size_;
};

template <typename PtrType>
class SYSTEM_PROCESS_INFORMATION_ENTRY_IMPL final : public SYSTEM_PROCESS_INFORMATION_ENTRY {
  public:
    uint32_t NextEntryOffset() const override { return this->data_->NextEntryOffset; }
    void NextEntryOffset(uint32_t NextEntryOffset) override {
        this->data_->NextEntryOffset = NextEntryOffset;
    };

    uint32_t NumberOfThreads() const override { return this->data_->NumberOfThreads; }
    void NumberOfThreads(uint32_t NumberOfThreads) override {
        this->data_->NumberOfThreads = NumberOfThreads;
    }

    int64_t WorkingSetPrivateSize() const override { return this->data_->WorkingSetPrivateSize; }
    void WorkingSetPrivateSize(int64_t WorkingSetPrivateSize) override {
        this->data_->WorkingSetPrivateSize = WorkingSetPrivateSize;
    }

    uint32_t HardFaultCount() const override { return this->data_->HardFaultCount; }
    void HardFaultCount(uint32_t HardFaultCount) override {
        this->data_->HardFaultCount = HardFaultCount;
    }

    uint32_t NumberOfThreadsHighWatermark() const override {
        return this->data_->NumberOfThreadsHighWatermark;
    }
    void NumberOfThreadsHighWatermark(uint32_t NumberOfThreadsHighWatermark) override {
        this->data_->NumberOfThreadsHighWatermark = NumberOfThreadsHighWatermark;
    }

    int64_t CycleTime() const override { return this->data_->CycleTime; }
    void CycleTime(int64_t CycleTime) override { this->data_->CycleTime = CycleTime; }

    WindowsTime CreateTime() const override {
        return WindowsTime::from_windows_time(this->data_->CreateTime);
    }
    void CreateTime(WindowsTime CreateTime) override {
        this->data_->CreateTime = CreateTime.windows_time();
    }

    int64_t UserTime() const override { return this->data_->UserTime; }
    void UserTime(int64_t UserTime) override { this->data_->UserTime = UserTime; }

    int64_t KernelTime() const override { return this->data_->KernelTime; }
    void KernelTime(int64_t KernelTime) override { this->data_->KernelTime = KernelTime; }

    std::string ImageName() const override { return ImageName_->utf8(); }
    void ImageName(const std::string& ImageName) override { ImageName_->set(ImageName); }

    int32_t BasePriority() const override { return this->data_->BasePriority; }
    void BasePriority(int32_t BasePriority) override { this->data_->BasePriority = BasePriority; }

    uint64_t UniqueProcessId() const override { return this->data_->UniqueProcessId; }
    void UniqueProcessId(uint64_t UniqueProcessId) override {
        this->data_->UniqueProcessId = UniqueProcessId;
    }

    uint64_t InheritedFromUniqueProcessId() const override {
        return this->data_->InheritedFromUniqueProcessId;
    }
    void InheritedFromUniqueProcessId(uint64_t InheritedFromUniqueProcessId) override {
        this->data_->InheritedFromUniqueProcessId = InheritedFromUniqueProcessId;
    }

    uint32_t HandleCount() const override { return this->data_->HandleCount; }
    void HandleCount(uint32_t HandleCount) override { this->data_->HandleCount = HandleCount; }

    uint32_t SessionId() const override { return this->data_->SessionId; }
    void SessionId(uint32_t SessionId) override { this->data_->SessionId = SessionId; }

    uint32_t UniqueProcessKey() const override { return this->data_->UniqueProcessKey; }
    void UniqueProcessKey(uint32_t UniqueProcessKey) override {
        this->data_->UniqueProcessKey = UniqueProcessKey;
    }

    const IO_COUNTERS& IOCounters() const override { return *IOCounters_; }
    IO_COUNTERS& IOCounters() override { return *IOCounters_; }

    const VM_COUNTERS& VMCounters() const override { return *VMCounters_; }
    VM_COUNTERS& VMCounters() override { return *VMCounters_; }

    GuestVirtualAddress address() const override { return gva_; }
    uint32_t buffer_size() const override {
        return offsetof(structs::_SYSTEM_PROCESS_INFORMATION<PtrType>, Threads) +
               Threads().buffer_size();
    }

    void write(std::ostream& os, const std::string& linePrefix = "") const override;
    Json::Value json() const override;

    const SYSTEM_PROCESS_INFORMATION_ENTRY::ThreadArray& Threads() const override {
        return *Threads_;
    }
    SYSTEM_PROCESS_INFORMATION_ENTRY::ThreadArray& Threads() override { return *Threads_; }

    SYSTEM_PROCESS_INFORMATION_ENTRY_IMPL(const GuestVirtualAddress& gva, uint32_t buffer_size)
        : gva_(gva) {

        if (unlikely(buffer_size < sizeof(structs::_SYSTEM_PROCESS_INFORMATION<PtrType>)))
            throw BufferTooSmallException(sizeof(structs::_SYSTEM_PROCESS_INFORMATION<PtrType>),
                                          buffer_size);

        data_.reset(gva_);
        ImageName_.emplace(gva_ +
                           offsetof(structs::_SYSTEM_PROCESS_INFORMATION<PtrType>, ImageName));

        VMCounters_.emplace(gva_ +
                            offsetof(structs::_SYSTEM_PROCESS_INFORMATION<PtrType>, VMCounters));

        IOCounters_.emplace(gva_ +
                            offsetof(structs::_SYSTEM_PROCESS_INFORMATION<PtrType>, IOCounters));

        auto pThreads = gva_ + offsetof(structs::_SYSTEM_PROCESS_INFORMATION<PtrType>, Threads);

        GuestVirtualAddress pEndThreads;
        if (NextEntryOffset()) {
            pEndThreads = pThreads + NextEntryOffset();
        } else {
            // Last entry in the buffer
            pEndThreads = gva_ + buffer_size;
        }

        Threads_.emplace(
            gva + offsetof(structs::_SYSTEM_PROCESS_INFORMATION<PtrType>, NumberOfThreads),
            pThreads, pEndThreads - pThreads);
    }

  private:
    const GuestVirtualAddress gva_;
    guest_ptr<structs::_SYSTEM_PROCESS_INFORMATION<PtrType>> data_;
    std::optional<UNICODE_STRING_IMPL<PtrType>> ImageName_;
    std::optional<IO_COUNTERS_IMPL> IOCounters_;
    std::optional<VM_COUNTERS_IMPL<PtrType>> VMCounters_;
    std::optional<ThreadArrayImpl<PtrType>> Threads_;
};

} // namespace nt
} // namespace windows
} // namespace introvirt