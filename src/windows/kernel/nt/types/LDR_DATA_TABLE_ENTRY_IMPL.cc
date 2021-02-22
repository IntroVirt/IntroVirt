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
#include "LDR_DATA_TABLE_ENTRY_IMPL.hh"
#include "windows/kernel/nt/types/UNICODE_STRING_IMPL.hh"

#include <introvirt/core/exception/MemoryException.hh>
#include <introvirt/core/memory/guest_ptr.hh>

#include <log4cxx/logger.h>

namespace introvirt {
namespace windows {
namespace nt {

static log4cxx::LoggerPtr
    logger(log4cxx::Logger::getLogger("introvirt.windows.kernel.nt.types.LDR_DATA_TABLE_ENTRY"));

template <typename PtrType>
GuestVirtualAddress LDR_DATA_TABLE_ENTRY_IMPL<PtrType>::DllBase() const {
    return gva_.create(data_->DllBase);
}

template <typename PtrType>
GuestVirtualAddress LDR_DATA_TABLE_ENTRY_IMPL<PtrType>::EntryPoint() const {
    return gva_.create(data_->EntryPoint);
}

template <typename PtrType>
uint32_t LDR_DATA_TABLE_ENTRY_IMPL<PtrType>::SizeOfImage() const {
    return data_->SizeOfImage;
}

template <typename PtrType>
void LDR_DATA_TABLE_ENTRY_IMPL<PtrType>::SizeOfImage(uint32_t value) {
    data_->SizeOfImage = value;
}

template <typename PtrType>
std::string LDR_DATA_TABLE_ENTRY_IMPL<PtrType>::FullDllName() const {
    if (FullDllName_.empty()) {
        const GuestVirtualAddress pFullDllName =
            gva_ + offsetof(structs::_LDR_DATA_TABLE_ENTRY<PtrType>, FullDllName);
        try {
            FullDllName_ = UNICODE_STRING_IMPL<PtrType>(pFullDllName).utf8();
        } catch (MemoryException& ex) {
            LOG4CXX_DEBUG(logger, "Exception getting FullDllName: " << ex.what());
        }
    }
    return FullDllName_;
}

template <typename PtrType>
std::string LDR_DATA_TABLE_ENTRY_IMPL<PtrType>::BaseDllName() const {
    if (BaseDllName_.empty()) {
        const GuestVirtualAddress pBaseDllName =
            gva_ + offsetof(structs::_LDR_DATA_TABLE_ENTRY<PtrType>, BaseDllName);
        try {
            BaseDllName_ = UNICODE_STRING_IMPL<PtrType>(pBaseDllName).utf8();
        } catch (MemoryException& ex) {
            LOG4CXX_DEBUG(logger, "Exception getting BaseDllName: " << ex.what());
        }
    }
    return BaseDllName_;
}

template <typename PtrType>
LDR_DATA_TABLE_ENTRY_IMPL<PtrType>::LDR_DATA_TABLE_ENTRY_IMPL(const GuestVirtualAddress& gva)
    : gva_(gva), data_(gva_) {}

template class LDR_DATA_TABLE_ENTRY_IMPL<uint32_t>;
template class LDR_DATA_TABLE_ENTRY_IMPL<uint64_t>;

} // namespace nt
} // namespace windows
} // namespace introvirt
