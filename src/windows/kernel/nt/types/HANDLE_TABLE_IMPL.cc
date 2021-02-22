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
#include "HANDLE_TABLE_IMPL.hh"
#include "HANDLE_TABLE_ENTRY_IMPL.hh"
#include "windows/kernel/nt/NtKernelImpl.hh"

#include <introvirt/core/exception/VirtualAddressNotPresentException.hh>
#include <introvirt/windows/WindowsGuest.hh>
#include <introvirt/windows/kernel/nt/NtKernel.hh>
#include <introvirt/windows/kernel/nt/const/ObjectType.hh>
#include <introvirt/windows/kernel/nt/types/HANDLE_TABLE_ENTRY.hh>
#include <introvirt/windows/kernel/nt/types/objects/CM_KEY_BODY.hh>
#include <introvirt/windows/kernel/nt/types/objects/DEVICE_OBJECT.hh>
#include <introvirt/windows/kernel/nt/types/objects/DRIVER_OBJECT.hh>
#include <introvirt/windows/kernel/nt/types/objects/FILE_OBJECT.hh>
#include <introvirt/windows/kernel/nt/types/objects/KEVENT.hh>
#include <introvirt/windows/kernel/nt/types/objects/OBJECT_DIRECTORY.hh>
#include <introvirt/windows/kernel/nt/types/objects/OBJECT_HEADER.hh>
#include <introvirt/windows/kernel/nt/types/objects/OBJECT_SYMBOLIC_LINK.hh>
#include <introvirt/windows/kernel/nt/types/objects/OBJECT_TYPE.hh>
#include <introvirt/windows/kernel/nt/types/objects/PROCESS.hh>
#include <introvirt/windows/kernel/nt/types/objects/SECTION.hh>
#include <introvirt/windows/kernel/nt/types/objects/THREAD.hh>
#include <introvirt/windows/kernel/nt/types/objects/TOKEN.hh>

#include <introvirt/windows/exception/InvalidStructureException.hh>

#include <log4cxx/logger.h>

#include <map>
#include <memory>
#include <mutex>
#include <type_traits>
#include <unordered_map>

namespace introvirt {
namespace windows {
namespace nt {

static log4cxx::LoggerPtr
    logger(log4cxx::Logger::getLogger("introvirt.windows.kernel.nt.types.HANDLE_TABLE"));

static constexpr uint64_t LEVEL_MASK = 0x3;

/* Handle Table */
template <typename PtrType>
std::shared_ptr<DEVICE_OBJECT> HANDLE_TABLE_IMPL<PtrType>::DeviceObject(uint64_t handle) {
    return ObjectByType<DEVICE_OBJECT, ObjectType::Device>(handle);
}

template <typename PtrType>
std::shared_ptr<const DEVICE_OBJECT>
HANDLE_TABLE_IMPL<PtrType>::DeviceObject(uint64_t handle) const {
    auto* non_const_this = const_cast<HANDLE_TABLE_IMPL<PtrType>*>(this);
    return non_const_this->DeviceObject(handle);
}

template <typename PtrType>
std::shared_ptr<OBJECT_DIRECTORY> HANDLE_TABLE_IMPL<PtrType>::DirectoryObject(uint64_t handle) {
    return ObjectByType<OBJECT_DIRECTORY, ObjectType::Directory>(handle);
}

template <typename PtrType>
std::shared_ptr<const OBJECT_DIRECTORY>
HANDLE_TABLE_IMPL<PtrType>::DirectoryObject(uint64_t handle) const {
    auto* non_const_this = const_cast<HANDLE_TABLE_IMPL<PtrType>*>(this);
    return non_const_this->DirectoryObject(handle);
}

template <typename PtrType>
std::shared_ptr<DRIVER_OBJECT> HANDLE_TABLE_IMPL<PtrType>::DriverObject(uint64_t handle) {
    return ObjectByType<DRIVER_OBJECT, ObjectType::Driver>(handle);
}

template <typename PtrType>
std::shared_ptr<const DRIVER_OBJECT>
HANDLE_TABLE_IMPL<PtrType>::DriverObject(uint64_t handle) const {
    auto* non_const_this = const_cast<HANDLE_TABLE_IMPL<PtrType>*>(this);
    return non_const_this->DriverObject(handle);
}

template <typename PtrType>
std::shared_ptr<KEVENT> HANDLE_TABLE_IMPL<PtrType>::EventObject(uint64_t handle) {
    return ObjectByType<KEVENT, ObjectType::Event>(handle);
}

template <typename PtrType>
std::shared_ptr<const KEVENT> HANDLE_TABLE_IMPL<PtrType>::EventObject(uint64_t handle) const {
    auto* non_const_this = const_cast<HANDLE_TABLE_IMPL<PtrType>*>(this);
    return non_const_this->EventObject(handle);
}

template <typename PtrType>
std::shared_ptr<FILE_OBJECT> HANDLE_TABLE_IMPL<PtrType>::FileObject(uint64_t handle) {
    return ObjectByType<FILE_OBJECT, ObjectType::File>(handle);
}

template <typename PtrType>
std::shared_ptr<const FILE_OBJECT> HANDLE_TABLE_IMPL<PtrType>::FileObject(uint64_t handle) const {
    auto* non_const_this = const_cast<HANDLE_TABLE_IMPL<PtrType>*>(this);
    return non_const_this->FileObject(handle);
}

template <typename PtrType>
std::shared_ptr<CM_KEY_BODY> HANDLE_TABLE_IMPL<PtrType>::KeyObject(uint64_t handle) {
    return ObjectByType<CM_KEY_BODY, ObjectType::Key>(handle);
}

template <typename PtrType>
std::shared_ptr<const CM_KEY_BODY> HANDLE_TABLE_IMPL<PtrType>::KeyObject(uint64_t handle) const {
    auto* non_const_this = const_cast<HANDLE_TABLE_IMPL<PtrType>*>(this);
    return non_const_this->KeyObject(handle);
}

template <typename PtrType>
std::shared_ptr<PROCESS> HANDLE_TABLE_IMPL<PtrType>::ProcessObject(uint64_t handle) {
    return ObjectByType<PROCESS, ObjectType::Process>(handle);
}

template <typename PtrType>
std::shared_ptr<const PROCESS> HANDLE_TABLE_IMPL<PtrType>::ProcessObject(uint64_t handle) const {
    auto* non_const_this = const_cast<HANDLE_TABLE_IMPL<PtrType>*>(this);
    return non_const_this->ProcessObject(handle);
}

template <typename PtrType>
std::shared_ptr<SECTION> HANDLE_TABLE_IMPL<PtrType>::SectionObject(uint64_t handle) {
    return ObjectByType<SECTION, ObjectType::Section>(handle);
}

template <typename PtrType>
std::shared_ptr<const SECTION> HANDLE_TABLE_IMPL<PtrType>::SectionObject(uint64_t handle) const {
    auto* non_const_this = const_cast<HANDLE_TABLE_IMPL<PtrType>*>(this);
    return non_const_this->SectionObject(handle);
}

template <typename PtrType>
std::shared_ptr<OBJECT_SYMBOLIC_LINK>
HANDLE_TABLE_IMPL<PtrType>::SymbolicLinkObject(uint64_t handle) {
    return ObjectByType<OBJECT_SYMBOLIC_LINK, ObjectType::SymbolicLink>(handle);
}

template <typename PtrType>
std::shared_ptr<const OBJECT_SYMBOLIC_LINK>
HANDLE_TABLE_IMPL<PtrType>::SymbolicLinkObject(uint64_t handle) const {
    auto* non_const_this = const_cast<HANDLE_TABLE_IMPL<PtrType>*>(this);
    return non_const_this->SymbolicLinkObject(handle);
}

template <typename PtrType>
std::shared_ptr<THREAD> HANDLE_TABLE_IMPL<PtrType>::ThreadObject(uint64_t handle) {
    return ObjectByType<THREAD, ObjectType::Thread>(handle);
}

template <typename PtrType>
std::shared_ptr<const THREAD> HANDLE_TABLE_IMPL<PtrType>::ThreadObject(uint64_t handle) const {
    auto* non_const_this = const_cast<HANDLE_TABLE_IMPL<PtrType>*>(this);
    return non_const_this->ThreadObject(handle);
}

template <typename PtrType>
std::shared_ptr<TOKEN> HANDLE_TABLE_IMPL<PtrType>::TokenObject(uint64_t handle) {
    return ObjectByType<TOKEN, ObjectType::Token>(handle);
}

template <typename PtrType>
std::shared_ptr<const TOKEN> HANDLE_TABLE_IMPL<PtrType>::TokenObject(uint64_t handle) const {
    auto* non_const_this = const_cast<HANDLE_TABLE_IMPL<PtrType>*>(this);
    return non_const_this->TokenObject(handle);
}

template <typename PtrType>
std::shared_ptr<OBJECT_TYPE> HANDLE_TABLE_IMPL<PtrType>::TypeObject(uint64_t handle) {
    return ObjectByType<OBJECT_TYPE, ObjectType::Type>(handle);
}

template <typename PtrType>
std::shared_ptr<const OBJECT_TYPE> HANDLE_TABLE_IMPL<PtrType>::TypeObject(uint64_t handle) const {
    auto* non_const_this = const_cast<HANDLE_TABLE_IMPL<PtrType>*>(this);
    return non_const_this->TypeObject(handle);
}

template <typename PtrType>
template <typename T, ObjectType ObjectType>
std::shared_ptr<T> HANDLE_TABLE_IMPL<PtrType>::ObjectByType(uint64_t handle) {
    std::shared_ptr<OBJECT> result = Object(handle);
    if (!result) {
        LOG4CXX_DEBUG(logger, "Object(" << std::hex << handle << ") returned nullptr");
        return nullptr;
    }

    if (unlikely(result->header().type() != ObjectType)) {
        LOG4CXX_DEBUG(logger, "Object type mismatch for handle 0x" << std::hex << handle);
        return nullptr;
    }

    return std::dynamic_pointer_cast<T>(result);
}

template <typename PtrType>
std::shared_ptr<OBJECT> HANDLE_TABLE_IMPL<PtrType>::Object(uint64_t handle) {
    try {
        auto handleEntry = Handle(handle);
        if (handleEntry->Value() == 0) {
            // Make sure we don't have a cached object for this handle
            LOG4CXX_DEBUG(logger, "Handle 0x" << std::hex << handle << " has empty value");
            return nullptr;
        }

        return OBJECT::make_shared(kernel_, handleEntry->ObjectHeader());
    } catch (InvalidStructureException& ex) {
        // One of the tables might have been null
        LOG4CXX_DEBUG(logger, "Invalid structure while trying to look up handle: " << ex.what());
        return nullptr;
    }
}

template <typename PtrType>
std::shared_ptr<const OBJECT> HANDLE_TABLE_IMPL<PtrType>::Object(uint64_t handle) const {
    auto* non_const_this = const_cast<HANDLE_TABLE_IMPL<PtrType>*>(this);
    return non_const_this->Object(handle);
}

template <typename PtrType>
std::unique_ptr<HANDLE_TABLE_ENTRY> HANDLE_TABLE_IMPL<PtrType>::Handle(uint64_t handle) {
    // The bottom two bits of the handle are used for something else
    handle &= 0xfffffffffffffffcll;

    if (unlikely(NextHandleNeedingPool() <= handle)) {
        // No entry. TODO, return NULLPTR.
        LOG4CXX_DEBUG(logger, "Handle out of bounds: 0x" << std::hex << handle
                                                         << " Max: " << NextHandleNeedingPool());
        throw InvalidStructureException("Handle out of bounds");
    }

    const PtrType TableCode = offsets_->TableCode.get<PtrType>(buffer_);
    const PtrType TableLevel = TableCode & LEVEL_MASK;

    if (unlikely(TableLevel > 2))
        throw InvalidStructureException("Invalid Table Code");

    GuestVirtualAddress pTable(gva_.create(TableCode & ~LEVEL_MASK));
    GuestVirtualAddress pEntry;

    if constexpr (std::is_same_v<PtrType, uint32_t>) {
        // 32-Bit implementation
        constexpr PtrType INDEX_MULTIPLIER = 2;
        constexpr PtrType L2_SHIFT = 21;
        constexpr PtrType L1_SHIFT = 11;

        if (TableLevel != 0) {
            if (TableLevel == 1) {
                // Level 1
                if (unlikely(!pTable))
                    throw InvalidStructureException("Null level-1 handle table");

                pTable += (handle >> L1_SHIFT) * sizeof(PtrType);
                pTable = pTable.create(*guest_ptr<PtrType>(pTable));
            } else {
                // Level 2
                if (unlikely(!pTable))
                    throw InvalidStructureException("Null level-2 handle table");
                pTable += (handle >> L2_SHIFT) * sizeof(PtrType);
                pTable = pTable.create(*guest_ptr<PtrType>(pTable));

                // Level 1
                if (unlikely(!pTable))
                    throw InvalidStructureException("Null level-1 handle table");
                pTable += ((handle >> L1_SHIFT) & 0x3ff) * sizeof(PtrType);
                pTable = pTable.create(*guest_ptr<PtrType>(pTable));
            }
            if (unlikely(!pTable))
                throw InvalidStructureException("Null level-0 handle table");
            pEntry = pTable + ((handle & 0x7fc) * INDEX_MULTIPLIER);
        } else {
            // Level 0
            if (unlikely(!pTable))
                throw InvalidStructureException("Null level-0 handle table");
            pEntry = pTable + (handle * INDEX_MULTIPLIER);
        }
    } else {
        // 64-Bit implementation
        constexpr PtrType INDEX_MULTIPLIER = 4;
        constexpr PtrType L2_SHIFT = 19;
        constexpr PtrType L1_MASK = 0x1ff;
        constexpr PtrType L1_SHIFT = 10;
        constexpr PtrType L0_MASK = 0x3ff;

        switch (TableLevel) {
        case 2:
            // Get the value from the L2 table
            if (unlikely(!pTable))
                throw InvalidStructureException("Null level-2 handle table");
            pTable += (handle >> L2_SHIFT) * sizeof(PtrType);
            pTable = pTable.create(*guest_ptr<PtrType>(pTable));

            // Get the value from the L1 table
            if (unlikely(!pTable))
                throw InvalidStructureException("Null level-1 handle table");
            pTable += ((handle >> L1_SHIFT) & L1_MASK) * sizeof(PtrType);
            pTable = pTable.create(*guest_ptr<PtrType>(pTable));

            // Get the address of the L0 entry
            if (unlikely(!pTable))
                throw InvalidStructureException("Null level-0 handle table");
            pEntry = pTable + (handle & L0_MASK) * INDEX_MULTIPLIER;
            break;
        case 1:
            // Get the value from the L1 table
            if (unlikely(!pTable))
                throw InvalidStructureException("Null level-1 handle table");

            pTable += (handle >> L1_SHIFT) * sizeof(PtrType);
            pTable = pTable.create(*guest_ptr<PtrType>(pTable));

            // Get the address of the L0 entry
            if (unlikely(!pTable))
                throw InvalidStructureException("Null level-0 handle table");
            pEntry = pTable + (handle & L0_MASK) * INDEX_MULTIPLIER;
            break;
        case 0:
            // Get the address of the L0 entry
            if (unlikely(!pTable))
                throw InvalidStructureException("Null level-0 handle table");
            pEntry = pTable + handle * INDEX_MULTIPLIER;
            break;
        }
    }
    return std::make_unique<HANDLE_TABLE_ENTRY_IMPL<PtrType>>(kernel_, pEntry, handle,
                                                              isPspCidTable);
}

template <typename PtrType>
std::unique_ptr<const HANDLE_TABLE_ENTRY>
HANDLE_TABLE_IMPL<PtrType>::Handle(uint64_t handle) const {
    auto* non_const_this = const_cast<HANDLE_TABLE_IMPL<PtrType>*>(this);
    return non_const_this->Handle(handle);
}

template <typename PtrType>
void HANDLE_TABLE_IMPL<PtrType>::parse_open_handles_l2(
    GuestVirtualAddress TableAddress,
    std::vector<std::unique_ptr<const HANDLE_TABLE_ENTRY>>& handles) const {

    constexpr unsigned int MaxCount = PageDirectory::PAGE_SIZE / sizeof(PtrType);
    guest_ptr<PtrType[]> entries(TableAddress, MaxCount);
    for (unsigned int i = 0; i < MaxCount; ++i) {
        if (entries[i]) {
            constexpr unsigned int Shift = (std::is_same_v<uint64_t, PtrType> ? 19 : 21);
            parse_open_handles_l1(TableAddress.create(entries[i]), handles, i << Shift);
        }
    }
}

template <typename PtrType>
void HANDLE_TABLE_IMPL<PtrType>::parse_open_handles_l1(
    GuestVirtualAddress TableAddress,
    std::vector<std::unique_ptr<const HANDLE_TABLE_ENTRY>>& handles, PtrType handle_start) const {
    constexpr unsigned int MaxCount = PageDirectory::PAGE_SIZE / sizeof(PtrType);
    guest_ptr<PtrType[]> entries(TableAddress, MaxCount);
    for (unsigned int i = 0; i < MaxCount; ++i) {
        if (entries[i]) {
            try {
                constexpr unsigned int Shift = (std::is_same_v<uint64_t, PtrType> ? 10 : 11);
                parse_open_handles_l0(TableAddress.create(entries[i]), handles, i << Shift);
            } catch (VirtualAddressNotPresentException& ex) {
                /*
                 * Note: This seems to be legitimate sometimes.
                 *       WinDbg is also unable to read any handle information for a process.
                 */
                LOG4CXX_DEBUG(logger,
                              "Could not read handle data at " << TableAddress.create(entries[i]));
            }
        }
    }
}

template <typename PtrType>
void HANDLE_TABLE_IMPL<PtrType>::parse_open_handles_l0(
    GuestVirtualAddress TableAddress,
    std::vector<std::unique_ptr<const HANDLE_TABLE_ENTRY>>& handles, PtrType handle_start) const {

    auto handle_table_entry_offsets = LoadOffsets<structs::HANDLE_TABLE_ENTRY>(kernel_);
    const unsigned int EntrySize = handle_table_entry_offsets->size();
    const unsigned int MaxCount = PageDirectory::PAGE_SIZE / EntrySize;

    for (unsigned int i = 0; i < MaxCount; ++i) {
        auto entry = std::make_unique<HANDLE_TABLE_ENTRY_IMPL<PtrType>>(
            kernel_, TableAddress + (i * EntrySize), handle_start + (i * 4), isPspCidTable);

        if (entry->Value() != 0u) {
            handles.push_back(std::move(entry));
        }
    }
}

template <typename PtrType>
std::vector<std::unique_ptr<const HANDLE_TABLE_ENTRY>>
HANDLE_TABLE_IMPL<PtrType>::open_handles() const {
    std::vector<std::unique_ptr<const HANDLE_TABLE_ENTRY>> result;

    const PtrType TableCode = offsets_->TableCode.get<PtrType>(buffer_);
    const PtrType TableLevel = TableCode & LEVEL_MASK;
    if (unlikely(TableLevel > 2))
        throw InvalidStructureException("Invalid Table Code");

    const GuestVirtualAddress TableAddress(gva_.create(TableCode & ~LEVEL_MASK));

    if (TableLevel == 2)
        parse_open_handles_l2(TableAddress, result);
    else if (TableLevel == 1)
        parse_open_handles_l1(TableAddress, result);
    else if (TableLevel == 0) {
        try {
            parse_open_handles_l0(TableAddress, result);
        } catch (VirtualAddressNotPresentException& ex) {
            /*
             * Note: This seems to be legitimate sometimes.
             *       WinDbg is also unable to read any handle information for a process.
             */
            LOG4CXX_DEBUG(logger, "Could not read handle data at " << TableAddress);
        }
    }

    return result;
}

template <typename PtrType>
int32_t HANDLE_TABLE_IMPL<PtrType>::HandleCount() const {
    if (offsets_->FreeLists.exists()) {
        const uint32_t ExpFreeListCount = *guest_ptr<uint32_t>(kernel_.symbol("ExpFreeListCount"));
        const auto& handle_table_free_list_offsets =
            LoadOffsets<structs::HANDLE_TABLE_FREE_LIST>(kernel_);

        int32_t result = 0;
        uint64_t FreeListsOffsets = offsets_->FreeLists;

        for (uint32_t i = 0; i < ExpFreeListCount; ++i) {
            auto FreeListBuffer = buffer_.get() + FreeListsOffsets;
            result +=
                handle_table_free_list_offsets->HandleCount.template get<int32_t>(FreeListBuffer);
            FreeListsOffsets += handle_table_free_list_offsets->size();
        }
        return result;
    } else if (offsets_->HandleCount.exists()) {
        return offsets_->HandleCount.get<int32_t>(buffer_);
    } else {
        throw InvalidStructureException("HANDLE_TABLE_FREE_LIST missing FreeLists and HandleCount");
    }
}

template <typename PtrType>
uint32_t HANDLE_TABLE_IMPL<PtrType>::NextHandleNeedingPool() const {
    return offsets_->NextHandleNeedingPool.get<uint32_t>(buffer_);
}

template <typename PtrType>
HANDLE_TABLE_IMPL<PtrType>::HANDLE_TABLE_IMPL(const NtKernelImpl<PtrType>& kernel,
                                              const GuestVirtualAddress& gva, bool isPspCidTable)
    : kernel_(kernel), gva_(gva), offsets_(LoadOffsets<structs::HANDLE_TABLE>(kernel)),
      handle_table_entry_(LoadOffsets<structs::HANDLE_TABLE_ENTRY>(kernel_)),
      isPspCidTable(isPspCidTable) {

    // Map in the structure.
    buffer_.reset(gva_, offsets_->size());
}

template <typename PtrType>
HANDLE_TABLE_IMPL<PtrType>::~HANDLE_TABLE_IMPL() = default;

template class HANDLE_TABLE_IMPL<uint32_t>;
template class HANDLE_TABLE_IMPL<uint64_t>;

} // namespace nt
} // namespace windows
} // namespace introvirt
