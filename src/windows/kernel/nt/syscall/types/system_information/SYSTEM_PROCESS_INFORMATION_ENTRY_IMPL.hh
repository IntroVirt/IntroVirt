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

    ThreadArrayImpl(const guest_ptr<void> pEntryCount, const guest_ptr<void>& pFirstEntry,
                    uint32_t buffer_size)
        : ThreadArrayImplBase<PtrType>(pEntryCount, pFirstEntry), buffer_size_(buffer_size) {

        // TODO : Pass in buffer_size for bounds checking
    }

  private:
    const uint32_t buffer_size_;
};

template <typename PtrType>
class SYSTEM_PROCESS_INFORMATION_ENTRY_IMPL final : public SYSTEM_PROCESS_INFORMATION_ENTRY {

    using _SYSTEM_PROCESS_INFORMATION = structs::_SYSTEM_PROCESS_INFORMATION<PtrType>;

  public:
    uint32_t NextEntryOffset() const override { return this->ptr_->NextEntryOffset; }
    void NextEntryOffset(uint32_t NextEntryOffset) override {
        this->ptr_->NextEntryOffset = NextEntryOffset;
    };

    uint32_t NumberOfThreads() const override { return this->ptr_->NumberOfThreads; }
    void NumberOfThreads(uint32_t NumberOfThreads) override {
        this->ptr_->NumberOfThreads = NumberOfThreads;
    }

    int64_t WorkingSetPrivateSize() const override { return this->ptr_->WorkingSetPrivateSize; }
    void WorkingSetPrivateSize(int64_t WorkingSetPrivateSize) override {
        this->ptr_->WorkingSetPrivateSize = WorkingSetPrivateSize;
    }

    uint32_t HardFaultCount() const override { return this->ptr_->HardFaultCount; }
    void HardFaultCount(uint32_t HardFaultCount) override {
        this->ptr_->HardFaultCount = HardFaultCount;
    }

    uint32_t NumberOfThreadsHighWatermark() const override {
        return this->ptr_->NumberOfThreadsHighWatermark;
    }
    void NumberOfThreadsHighWatermark(uint32_t NumberOfThreadsHighWatermark) override {
        this->ptr_->NumberOfThreadsHighWatermark = NumberOfThreadsHighWatermark;
    }

    int64_t CycleTime() const override { return this->ptr_->CycleTime; }
    void CycleTime(int64_t CycleTime) override { this->ptr_->CycleTime = CycleTime; }

    WindowsTime CreateTime() const override {
        return WindowsTime::from_windows_time(this->ptr_->CreateTime);
    }
    void CreateTime(WindowsTime CreateTime) override {
        this->ptr_->CreateTime = CreateTime.windows_time();
    }

    int64_t UserTime() const override { return this->ptr_->UserTime; }
    void UserTime(int64_t UserTime) override { this->ptr_->UserTime = UserTime; }

    int64_t KernelTime() const override { return this->ptr_->KernelTime; }
    void KernelTime(int64_t KernelTime) override { this->ptr_->KernelTime = KernelTime; }

    std::string ImageName() const override { return ImageName_->utf8(); }
    void ImageName(const std::string& ImageName) override { ImageName_->set(ImageName); }

    int32_t BasePriority() const override { return this->ptr_->BasePriority; }
    void BasePriority(int32_t BasePriority) override { this->ptr_->BasePriority = BasePriority; }

    uint64_t UniqueProcessId() const override { return this->ptr_->UniqueProcessId; }
    void UniqueProcessId(uint64_t UniqueProcessId) override {
        this->ptr_->UniqueProcessId = UniqueProcessId;
    }

    uint64_t InheritedFromUniqueProcessId() const override {
        return this->ptr_->InheritedFromUniqueProcessId;
    }
    void InheritedFromUniqueProcessId(uint64_t InheritedFromUniqueProcessId) override {
        this->ptr_->InheritedFromUniqueProcessId = InheritedFromUniqueProcessId;
    }

    uint32_t HandleCount() const override { return this->ptr_->HandleCount; }
    void HandleCount(uint32_t HandleCount) override { this->ptr_->HandleCount = HandleCount; }

    uint32_t SessionId() const override { return this->ptr_->SessionId; }
    void SessionId(uint32_t SessionId) override { this->ptr_->SessionId = SessionId; }

    uint32_t UniqueProcessKey() const override { return this->ptr_->UniqueProcessKey; }
    void UniqueProcessKey(uint32_t UniqueProcessKey) override {
        this->ptr_->UniqueProcessKey = UniqueProcessKey;
    }

    const IO_COUNTERS& IOCounters() const override { return *IOCounters_; }
    IO_COUNTERS& IOCounters() override { return *IOCounters_; }

    const VM_COUNTERS& VMCounters() const override { return *VMCounters_; }
    VM_COUNTERS& VMCounters() override { return *VMCounters_; }

    guest_ptr<void> ptr() const override { return ptr_; }
    uint32_t buffer_size() const override {
        return offsetof(_SYSTEM_PROCESS_INFORMATION, Threads) + Threads().buffer_size();
    }

    void write(std::ostream& os, const std::string& linePrefix = "") const override;
    Json::Value json() const override;

    const SYSTEM_PROCESS_INFORMATION_ENTRY::ThreadArray& Threads() const override {
        return *Threads_;
    }
    SYSTEM_PROCESS_INFORMATION_ENTRY::ThreadArray& Threads() override { return *Threads_; }

    SYSTEM_PROCESS_INFORMATION_ENTRY_IMPL(const guest_ptr<void>& ptr, uint32_t buffer_size) {

        if (unlikely(buffer_size < sizeof(_SYSTEM_PROCESS_INFORMATION)))
            throw BufferTooSmallException(sizeof(_SYSTEM_PROCESS_INFORMATION), buffer_size);

        ptr_.reset(ptr);
        ImageName_.emplace(ptr + offsetof(_SYSTEM_PROCESS_INFORMATION, ImageName));

        VMCounters_.emplace(ptr + offsetof(_SYSTEM_PROCESS_INFORMATION, VMCounters));

        IOCounters_.emplace(ptr + offsetof(_SYSTEM_PROCESS_INFORMATION, IOCounters));

        auto pThreads = ptr + offsetof(_SYSTEM_PROCESS_INFORMATION, Threads);

        guest_ptr<void> pEndThreads;
        if (NextEntryOffset()) {
            pEndThreads = pThreads + NextEntryOffset();
        } else {
            // Last entry in the buffer
            pEndThreads = ptr + buffer_size;
        }

        Threads_.emplace(ptr + offsetof(_SYSTEM_PROCESS_INFORMATION, NumberOfThreads), pThreads,
                         pEndThreads.address() - pThreads.address());
    }

  private:
    guest_ptr<_SYSTEM_PROCESS_INFORMATION> ptr_;
    std::optional<UNICODE_STRING_IMPL<PtrType>> ImageName_;
    std::optional<IO_COUNTERS_IMPL> IOCounters_;
    std::optional<VM_COUNTERS_IMPL<PtrType>> VMCounters_;
    std::optional<ThreadArrayImpl<PtrType>> Threads_;
};

} // namespace nt
} // namespace windows
} // namespace introvirt