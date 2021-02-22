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

#include "SYSTEM_INFORMATION.hh"

#include <introvirt/windows/kernel/nt/const/KTHREAD_STATE.hh>
#include <introvirt/windows/kernel/nt/const/KWAIT_REASON.hh>
#include <introvirt/windows/kernel/nt/syscall/types/array_iterator.hh>
#include <introvirt/windows/kernel/nt/syscall/types/offset_iterator.hh>
#include <introvirt/windows/util/WindowsTime.hh>

#include <cstdint>
#include <ostream>
#include <string>

namespace introvirt {
namespace windows {
namespace nt {

class SYSTEM_THREAD {
  public:
    virtual int64_t KernelTime() const = 0;
    virtual void KernelTime(int64_t KernelTime) = 0;

    virtual int64_t UserTime() const = 0;
    virtual void UserTime(int64_t UserTime) = 0;

    virtual int64_t CreateTime() const = 0;
    virtual void CreateTime(int64_t CreateTime) = 0;

    virtual uint32_t WaitTime() const = 0;
    virtual void WaitTime(uint32_t WaitTime) = 0;

    virtual uint64_t StartAddress() const = 0;
    virtual void StartAddress(uint64_t StartAddress) = 0;

    virtual uint64_t UniqueProcessId() const = 0;
    virtual void UniqueProcessId(uint64_t UniqueProcessId) = 0;

    virtual uint64_t UniqueThreadId() const = 0;
    virtual void UniqueThreadId(uint64_t UniqueThreadId) = 0;

    virtual uint32_t Priority() const = 0;
    virtual void Priority(uint32_t Priority) = 0;

    virtual int32_t BasePriority() const = 0;
    virtual void BasePriority(int32_t BasePriority) = 0;

    virtual uint32_t ContextSwitchCount() const = 0;
    virtual void ContextSwitchCount(uint32_t ContextSwitchCount) = 0;

    virtual KTHREAD_STATE State() const = 0;
    virtual void State(KTHREAD_STATE State) = 0;

    virtual KWAIT_REASON WaitReason() const = 0;
    virtual void WaitReason(KWAIT_REASON WaitReason) = 0;

    virtual void write(std::ostream& os, const std::string& linePrefix = "") const = 0;
    virtual Json::Value json() const = 0;

    virtual GuestVirtualAddress address() const = 0;

    virtual ~SYSTEM_THREAD() = default;
};

class VM_COUNTERS {
  public:
    virtual uint64_t PeakVirtualSize() const = 0;
    virtual void PeakVirtualSize(uint64_t PeakVirtualSize) = 0;

    virtual uint64_t VirtualSize() const = 0;
    virtual void VirtualSize(uint64_t VirtualSize) = 0;

    virtual uint32_t PageFaultCount() const = 0;
    virtual void PageFaultCount(uint32_t PageFaultCount) = 0;

    virtual uint64_t PeakWorkingSetSize() const = 0;
    virtual void PeakWorkingSetSize(uint64_t PeakWorkingSetSize) = 0;

    virtual uint64_t WorkingSetSize() const = 0;
    virtual void WorkingSetSize(uint64_t WorkingSetSize) = 0;

    virtual uint64_t QuotaPeakPagedPoolUsage() const = 0;
    virtual void QuotaPeakPagedPoolUsage(uint64_t QuotaPeakPagedPoolUsage) = 0;

    virtual uint64_t QuotaPagedPoolUsage() const = 0;
    virtual void QuotaPagedPoolUsage(uint64_t QuotaPagedPoolUsage) = 0;

    virtual uint64_t QuotaPeakNonPagedPoolUsage() const = 0;
    virtual void QuotaPeakNonPagedPoolUsage(uint64_t QuotaPeakNonPagedPoolUsage) = 0;

    virtual uint64_t QuotaNonPagedPoolUsage() const = 0;
    virtual void QuotaNonPagedPoolUsage(uint64_t QuotaNonPagedPoolUsage) = 0;

    virtual uint64_t PagefileUsage() const = 0;
    virtual void PagefileUsage(uint64_t PagefileUsage) = 0;

    virtual uint64_t PeakPagefileUsage() const = 0;
    virtual void PeakPagefileUsage(uint64_t PeakPagefileUsage) = 0;

    virtual uint64_t PrivatePageCount() const = 0;
    virtual void PrivatePageCount(uint64_t PrivatePageCount) = 0;

    virtual void write(std::ostream& os, const std::string& linePrefix = "") const = 0;
    virtual Json::Value json() const = 0;

    virtual GuestVirtualAddress address() const = 0;

    virtual ~VM_COUNTERS() = default;
};

class IO_COUNTERS {
  public:
    virtual uint64_t ReadOperationCount() const = 0;
    virtual void ReadOperationCount(uint64_t value) = 0;

    virtual uint64_t WriteOperationCount() const = 0;
    virtual void WriteOperationCount(uint64_t value) = 0;

    virtual uint64_t OtherOperationCount() const = 0;
    virtual void OtherOperationCount(uint64_t value) = 0;

    virtual uint64_t ReadTransferCount() const = 0;
    virtual void ReadTransferCount(uint64_t value) = 0;

    virtual uint64_t WriteTransferCount() const = 0;
    virtual void WriteTransferCount(uint64_t value) = 0;

    virtual uint64_t OtherTransferCount() const = 0;
    virtual void OtherTransferCount(uint64_t value) = 0;

    virtual void write(std::ostream& os, const std::string& linePrefix = "") const = 0;
    virtual Json::Value json() const = 0;

    virtual GuestVirtualAddress address() const = 0;

    virtual ~IO_COUNTERS() = default;
};

class SYSTEM_PROCESS_INFORMATION_ENTRY {
  public:
    virtual uint32_t NextEntryOffset() const = 0;
    virtual void NextEntryOffset(uint32_t value) = 0;

    virtual uint32_t NumberOfThreads() const = 0;
    virtual void NumberOfThreads(uint32_t NumberOfThreads) = 0;

    virtual int64_t WorkingSetPrivateSize() const = 0;
    virtual void WorkingSetPrivateSize(int64_t WorkingSetPrivateSize) = 0;

    virtual uint32_t HardFaultCount() const = 0;
    virtual void HardFaultCount(uint32_t HardFaultCount) = 0;

    virtual uint32_t NumberOfThreadsHighWatermark() const = 0;
    virtual void NumberOfThreadsHighWatermark(uint32_t NumberOfThreadsHighWatermark) = 0;

    virtual int64_t CycleTime() const = 0;
    virtual void CycleTime(int64_t CycleTime) = 0;

    virtual WindowsTime CreateTime() const = 0;
    virtual void CreateTime(WindowsTime CreateTime) = 0;

    virtual int64_t UserTime() const = 0;
    virtual void UserTime(int64_t UserTime) = 0;

    virtual int64_t KernelTime() const = 0;
    virtual void KernelTime(int64_t KernelTime) = 0;

    virtual std::string ImageName() const = 0;
    virtual void ImageName(const std::string& ImageName) = 0;

    virtual int32_t BasePriority() const = 0;
    virtual void BasePriority(int32_t BasePriority) = 0;

    virtual uint64_t UniqueProcessId() const = 0;
    virtual void UniqueProcessId(uint64_t UniqueProcessId) = 0;

    virtual uint64_t InheritedFromUniqueProcessId() const = 0;
    virtual void InheritedFromUniqueProcessId(uint64_t InheritedFromUniqueProcessId) = 0;

    virtual uint32_t HandleCount() const = 0;
    virtual void HandleCount(uint32_t HandleCount) = 0;

    virtual uint32_t SessionId() const = 0;
    virtual void SessionId(uint32_t SessionId) = 0;

    virtual uint32_t UniqueProcessKey() const = 0;
    virtual void UniqueProcessKey(uint32_t UniqueProcessKey) = 0;

    virtual const VM_COUNTERS& VMCounters() const = 0;
    virtual VM_COUNTERS& VMCounters() = 0;

    virtual const IO_COUNTERS& IOCounters() const = 0;
    virtual IO_COUNTERS& IOCounters() = 0;

    class ThreadArray {
      public:
        using iterator = array_iterator<SYSTEM_THREAD, ThreadArray, false>;
        using const_iterator = array_iterator<SYSTEM_THREAD, ThreadArray, true>;
        /**
         * @brief Get an entry at the specified index
         *
         * @param index The index into the array
         * @return PS_ATTRIBUTE&
         */
        virtual SYSTEM_THREAD& operator[](uint32_t index) = 0;
        virtual const SYSTEM_THREAD& operator[](uint32_t index) const = 0;

        /**
         * @copydoc PS_ATTRIBUTE_LIST::operator[](uint32_t)
         *
         * @param index
         * @return PS_ATTRIBUTE&
         */
        virtual SYSTEM_THREAD& at(uint32_t index) = 0;
        virtual const SYSTEM_THREAD& at(uint32_t index) const = 0;

        /**
         * @brief Remove an element from the list
         *
         * @param iter An iter to the element to remove
         * @return const_iterator containing the next element after the erased one
         */
        virtual iterator erase(const const_iterator& iter) = 0;

        /**
         * @brief Get the number of entries
         *
         * @return uint32_t
         */
        virtual uint32_t length() const = 0;

        /**
         * @brief Get an iterator to the first entry
         *
         * @return const_iterator
         */
        virtual iterator begin() = 0;

        /**
         * @brief Get the end iterator
         *
         * @return const_iterator
         */
        virtual iterator end() = 0;

        /**
         * @brief Get an iterator to the first entry
         *
         * @return const_iterator
         */
        virtual const_iterator begin() const = 0;

        /**
         * @brief Get the end iterator
         *
         * @return const_iterator
         */
        virtual const_iterator end() const = 0;

        /**
         * @brief Get the total size of the buffer in bytes
         *
         * This may not relate to the total number of entries;
         * the buffer could be larger than necessary, for example.
         *
         * @return uint32_t
         */
        virtual uint32_t buffer_size() const = 0;

        /**
         * @brief Write out a human-readable representation
         *
         * @param os
         * @param linePrefix
         */
        virtual void write(std::ostream& os, const std::string& linePrefix = "") const = 0;

        /**
         * @brief Get a Json respresentation of the buffer
         *
         * @return Json::Value
         */
        virtual Json::Value json() const = 0;
    };

    virtual const ThreadArray& Threads() const = 0;
    virtual ThreadArray& Threads() = 0;

    virtual void write(std::ostream& os, const std::string& linePrefix = "") const = 0;
    virtual Json::Value json() const = 0;

    virtual GuestVirtualAddress address() const = 0;
    virtual uint32_t buffer_size() const = 0;

    virtual ~SYSTEM_PROCESS_INFORMATION_ENTRY() = default;
};

class SYSTEM_PROCESS_INFORMATION : public SYSTEM_INFORMATION {
  public:
    using iterator = offset_iterator<SYSTEM_PROCESS_INFORMATION_ENTRY, false>;
    using const_iterator = offset_iterator<SYSTEM_PROCESS_INFORMATION_ENTRY, true>;

    virtual iterator begin() = 0;
    virtual iterator end() = 0;
    virtual iterator erase(const const_iterator& position) = 0;

    virtual const_iterator begin() const = 0;
    virtual const_iterator end() const = 0;
};

} /* namespace nt */
} /* namespace windows */
} /* namespace introvirt */
