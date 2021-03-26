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

#include "windows/kernel/nt/structs/base.hh"
#include "windows/kernel/nt/types/UNICODE_STRING_IMPL.hh"

#include <introvirt/core/exception/MemoryException.hh>
#include <introvirt/windows/kernel/nt/types/LDR_DATA_TABLE_ENTRY.hh>

#include <log4cxx/logger.h>

namespace introvirt {
namespace windows {
namespace nt {

namespace structs {

template <typename PtrType>
struct _LDR_DATA_TABLE_ENTRY {
    _LIST_ENTRY<PtrType> InLoadOrderLinks;
    _LIST_ENTRY<PtrType> InMemoryOrderLinks;
    _LIST_ENTRY<PtrType> InInitializationOrderLinks;
    guest_member_ptr<void, PtrType> DllBase;
    guest_member_ptr<void, PtrType> EntryPoint;
    ULONG SizeOfImage;
    _UNICODE_STRING<PtrType> FullDllName;
    _UNICODE_STRING<PtrType> BaseDllName;
};

static_assert(offsetof(_LDR_DATA_TABLE_ENTRY<uint32_t>, BaseDllName) == 0x2c);
static_assert(offsetof(_LDR_DATA_TABLE_ENTRY<uint64_t>, BaseDllName) == 0x58);

} // namespace structs

template <typename PtrType>
class NtKernelImpl;

template <typename PtrType>
class LDR_DATA_TABLE_ENTRY_IMPL final : public LDR_DATA_TABLE_ENTRY {
  private:
    static inline log4cxx::LoggerPtr logger =
        log4cxx::Logger::getLogger("introvirt.windows.kernel.nt.types.LDR_DATA_TABLE_ENTRY");

  public:
    //
    // Note: These are returning uint64_t because some seem to be in different address spaces, and
    // can't be mapped
    //

    /**
     * @returns The base address of this entry
     */
    uint64_t DllBase() const override { return data_->DllBase.raw(); }

    /**
     * @returns The entry point of this entry
     */
    uint64_t EntryPoint() const override { return data_->EntryPoint.raw(); }

    /**
     * @returns The size of this entry
     */
    uint32_t SizeOfImage() const override { return data_->SizeOfImage; }
    void SizeOfImage(uint32_t value) override { data_->SizeOfImage = value; }

    /**
     * @returns The full dll name of this entry, or NULL if unavailable
     */
    std::string FullDllName() const override {
        if (FullDllName_.empty()) {
            const guest_ptr<void> pFullDllName =
                ptr_ + offsetof(_LDR_DATA_TABLE_ENTRY, FullDllName);
            try {
                FullDllName_ = UNICODE_STRING_IMPL<PtrType>(pFullDllName).utf8();
            } catch (MemoryException& ex) {
                LOG4CXX_DEBUG(logger, "Exception getting FullDllName: " << ex.what());
            }
        }
        return FullDllName_;
    }

    /**
     * @returns The base dll name of this entry, or NULL if unavailable
     */
    std::string BaseDllName() const override {
        if (BaseDllName_.empty()) {
            const guest_ptr<void> pBaseDllName =
                ptr_ + offsetof(_LDR_DATA_TABLE_ENTRY, BaseDllName);
            try {
                BaseDllName_ = UNICODE_STRING_IMPL<PtrType>(pBaseDllName).utf8();
            } catch (MemoryException& ex) {
                LOG4CXX_DEBUG(logger, "Exception getting BaseDllName: " << ex.what());
            }
        }
        return BaseDllName_;
    }

    guest_ptr<void> ptr() const override { return ptr_; }

    LDR_DATA_TABLE_ENTRY_IMPL(const guest_ptr<void>& ptr) : ptr_(ptr), data_(ptr) {}

  private:
    using _LDR_DATA_TABLE_ENTRY = structs::_LDR_DATA_TABLE_ENTRY<PtrType>;
    const guest_ptr<void> ptr_;
    const guest_ptr<_LDR_DATA_TABLE_ENTRY> data_;

    mutable std::string BaseDllName_;
    mutable std::string FullDllName_;
};

} // namespace nt
} // namespace windows
} // namespace introvirt