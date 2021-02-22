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
#include "HANDLE_TABLE_ENTRY_IMPL.hh"
#include "windows/kernel/nt/NtKernelImpl.hh"
#include "windows/kernel/nt/types/objects/OBJECT_HEADER_IMPL.hh"

#include <introvirt/windows/exception/InvalidStructureException.hh>
#include <introvirt/windows/kernel/nt/NtKernel.hh>
#include <introvirt/windows/kernel/nt/types/access_mask/ACCESS_MASK.hh>
#include <introvirt/windows/kernel/nt/types/objects/OBJECT_HEADER.hh>

#include <log4cxx/logger.h>

#include <memory>

using namespace std;

namespace introvirt {
namespace windows {
namespace nt {

static log4cxx::LoggerPtr
    logger(log4cxx::Logger::getLogger("introvirt.windows.kernel.nt.types.HANDLE_TABLE_ENTRY"));

template <typename PtrType>
uint64_t HANDLE_TABLE_ENTRY_IMPL<PtrType>::Handle() const {
    return handle;
}

template <typename PtrType>
std::unique_ptr<OBJECT_HEADER> HANDLE_TABLE_ENTRY_IMPL<PtrType>::ObjectHeader() const {
    GuestVirtualAddress pObjectHeader = gva_.create(Value());
    if (unlikely(!pObjectHeader))
        throw InvalidStructureException("NULL value in HANDLE_TABLE_ENTRY::ObjectHeader()");

    if (isPspCidTable) {
        const auto& object_header_offsets = LoadOffsets<structs::OBJECT_HEADER>(kernel_);
        pObjectHeader -= object_header_offsets->Body;
    }

    return std::make_unique<OBJECT_HEADER_IMPL<PtrType>>(kernel_, pObjectHeader);
}

template <typename PtrType>
ACCESS_MASK HANDLE_TABLE_ENTRY_IMPL<PtrType>::GrantedAccess() const {
    // TODO(papes): Check the object type first
    // Then we can return the right kind of ACCESS_MASK

    if (offsets_->GrantedAccessBits.exists()) {
        // New style
        return offsets_->GrantedAccessBits.get_bitfield<uint32_t>(buffer_);
    } else if (offsets_->GrantedAccess.exists()) {
        // Old style
        return offsets_->GrantedAccess.get<uint32_t>(buffer_);
    } else {
        throw InvalidStructureException(
            "Missing HANDLE_TABLE_ENTRY::GrantedAccessBits/GrantedAccess");
    }
}

template <typename PtrType>
void HANDLE_TABLE_ENTRY_IMPL<PtrType>::GrantedAccess(const ACCESS_MASK& mask) {
    if (offsets_->GrantedAccessBits.exists()) {
        // New style
        offsets_->GrantedAccessBits.set_bitfield<uint32_t>(buffer_, mask.value());
    } else if (offsets_->GrantedAccess.exists()) {
        // Old style
        offsets_->GrantedAccess.set<uint32_t>(buffer_, mask.value());
    } else {
        throw InvalidStructureException(
            "Missing HANDLE_TABLE_ENTRY::GrantedAccessBits/GrantedAccess");
    }
}

template <typename PtrType>
uint64_t HANDLE_TABLE_ENTRY_IMPL<PtrType>::Value() const {
    if (offsets_->ObjectPointerBits.exists()) {
        // 8.1+ (presumably)
        const PtrType ObjectPointer = offsets_->ObjectPointerBits.get_bitfield<PtrType>(buffer_);

        if constexpr (std::is_same_v<PtrType, uint64_t>) {
            // 64-Bit
            // TODO: Not sure what ObjectPointer value 0xfffffffffff actually means,
            //       but obviously we can't dereference it.
            if (ObjectPointer != 0 && ObjectPointer != 0xfffffffffff) {
                return 0xFFFF000000000000LL | (ObjectPointer << 4LL);
            }
            return 0;
        } else {
            // 32-Bit
            return ObjectPointer << 3;
        }
    } else if (offsets_->Value.exists()) {
        // Pre Windows 8.1 (presumably, definitely XP and 7)
        return offsets_->Value.get<PtrType>(buffer_);
    } else {
        throw InvalidStructureException("Missing HANDLE_TABLE_ENTRY::ObjectPointerBits/Value");
    }
}

template <typename PtrType>
GuestVirtualAddress HANDLE_TABLE_ENTRY_IMPL<PtrType>::address() const {
    return gva_;
}

template <typename PtrType>
HANDLE_TABLE_ENTRY_IMPL<PtrType>::HANDLE_TABLE_ENTRY_IMPL(const NtKernelImpl<PtrType>& kernel,
                                                          const GuestVirtualAddress& gva,
                                                          uint64_t handle, bool isPspCidTable)
    : kernel_(kernel), gva_(gva), handle(handle), isPspCidTable(isPspCidTable),
      offsets_(LoadOffsets<structs::HANDLE_TABLE_ENTRY>(kernel)) {

    // Map in the structure.
    buffer_.reset(gva, offsets_->size());
}

template <typename PtrType>
HANDLE_TABLE_ENTRY_IMPL<PtrType>::~HANDLE_TABLE_ENTRY_IMPL() = default;

template class HANDLE_TABLE_ENTRY_IMPL<uint32_t>;
template class HANDLE_TABLE_ENTRY_IMPL<uint64_t>;

} /* namespace nt */
} /* namespace windows */
} /* namespace introvirt */
