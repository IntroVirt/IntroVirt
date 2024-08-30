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
#include "HIVE_IMPL.hh"
#include "CM_KEY_NODE_IMPL.hh"
#include "windows/kernel/nt/NtKernelImpl.hh"
#include "windows/kernel/nt/types/UNICODE_STRING_IMPL.hh"

#include <introvirt/windows/exception/InvalidStructureException.hh>

namespace introvirt {
namespace windows {
namespace nt {

template <typename PtrType>
const HIVE* HIVE_IMPL<PtrType>::PreviousHive() const {
    if (!PreviousHive_.get()) {
        try {
            const guest_ptr<void> pPreviousHive = ptr_.clone(
                cmhive_->HiveList.Blink.get<PtrType>(cmhive_buffer_) - cmhive_->HiveList.offset());
            PreviousHive_ = std::make_unique<HIVE_IMPL<PtrType>>(kernel_, pPreviousHive);
        } catch (TraceableException& ex) {
            LOG4CXX_WARN(logger, "PreviousHive() failed: " << ex);
            return nullptr;
        }
    }
    return PreviousHive_.get();
}

template <typename PtrType>
const HIVE* HIVE_IMPL<PtrType>::NextHive() const {
    if (!NextHive_.get()) {
        try {
            const guest_ptr<void> pNextHive = ptr_.clone(
                cmhive_->HiveList.Flink.get<PtrType>(cmhive_buffer_) - cmhive_->HiveList.offset());
            NextHive_ = std::make_unique<HIVE_IMPL<PtrType>>(kernel_, pNextHive);
        } catch (TraceableException& ex) {
            LOG4CXX_WARN(logger, "NextHive() threw exception: " << ex);
            return nullptr;
        }
    }
    return NextHive_.get();
}

template <typename PtrType>
const std::string& HIVE_IMPL<PtrType>::FileFullPath() const {
    if (FileFullPath_.empty()) {
        const guest_ptr<void> addr = ptr_ + cmhive_->FileFullPath.offset();
        FileFullPath_ = UNICODE_STRING_IMPL<PtrType>(addr).utf8();
    }
    return FileFullPath_;
}

template <typename PtrType>
const std::string& HIVE_IMPL<PtrType>::FileUserName() const {
    if (FileUserName_.empty()) {
        FileUserName_ = UNICODE_STRING_IMPL<PtrType>(ptr_ + cmhive_->FileUserName.offset()).utf8();
    }
    return FileUserName_;
}

template <typename PtrType>
const std::string& HIVE_IMPL<PtrType>::HiveRootPath() const {
    if (HiveRootPath_.empty()) {
        if (cmhive_->HiveRootPath.exists()) {
            HiveRootPath_ =
                UNICODE_STRING_IMPL<PtrType>(ptr_ + cmhive_->HiveRootPath.offset()).utf8();
        }
    }
    return HiveRootPath_;
}

template <typename PtrType>
const HBASE_BLOCK& HIVE_IMPL<PtrType>::BaseBlock() const {
    if (!BaseBlock_) {
        const guest_ptr<void> pBaseBlock =
            ptr_.clone(cmhive_->Hive.BaseBlock.get<PtrType>(cmhive_buffer_));
        LOG4CXX_DEBUG(logger, "BaseBlock: " << pBaseBlock);
        BaseBlock_.emplace(kernel_, pBaseBlock);
    }
    return *BaseBlock_;
}

template <typename PtrType>
const CM_KEY_NODE* HIVE_IMPL<PtrType>::RootKeyNode() const {
    uint32_t rootCell = 0x20;

    try {
        /* Try to verify the rootCell, but in practice it's always 0x20 anyway */
        rootCell = BaseBlock().RootCell();
        LOG4CXX_DEBUG(logger, "RootCell: 0x" << std::hex << rootCell);
    } catch (TraceableException& ex) {
        LOG4CXX_WARN(logger, "RootKeyNode() threw exception: " << ex);
    }

    return KeyNode(rootCell);
}

template <typename PtrType>
const CM_KEY_NODE* HIVE_IMPL<PtrType>::KeyNode(uint32_t KeyIndex) const {
    auto iter = KeyIndexNodeMap_.find(KeyIndex);
    if (iter != KeyIndexNodeMap_.end())
        return iter->second.get();

    const guest_ptr<void> pCell = CellAddress(KeyIndex);
    if (!pCell)
        return nullptr;

    auto result = KeyIndexNodeMap_.emplace(std::make_pair(
        KeyIndex, std::make_unique<CM_KEY_NODE_IMPL<PtrType>>(kernel_, *this, pCell)));

    return result.first->second.get();
}

template <typename PtrType>
uint32_t HIVE_IMPL<PtrType>::HiveFlags() const {
    return cmhive_->Hive.HiveFlags.get<uint32_t>(cmhive_buffer_);
}

template <typename PtrType>
guest_ptr<void> HIVE_IMPL<PtrType>::CellAddress(uint32_t KeyIndex) const {
    union KeyIndexBits {
        struct {
            uint32_t Offset : 12;
            uint32_t Entry : 9;
            uint32_t Table : 10;
            uint32_t Volatile : 1;
        };
        uint32_t KeyIndex;
    };

    KeyIndexBits bits{.KeyIndex = KeyIndex};

    try {
        const uint32_t topTableOffset =
            cmhive_->Hive.Storage.offset() + (dual_->size() * bits.Volatile);
        guest_ptr<char[]> topTableBuffer(ptr_ + topTableOffset, dual_->size());
        const guest_ptr<void> pDirectory = ptr_.clone(dual_->Map.get<PtrType>(topTableBuffer));

        /* Offset into the directory, which is an array of pointers, to get the HMAP_TABLE
         * pointer */
        const guest_ptr<void> ppTable = pDirectory + (sizeof(PtrType) * bits.Table);
        const guest_ptr<void> pTable = ptr_.clone(*guest_ptr<PtrType>(ppTable));

        /* Offset into the table, which is an array of _HMAP_ENTRYs, to get the specific entry
         */
        const guest_ptr<void> pEntry = pTable + (hmap_entry_->size() * bits.Entry);
        const guest_ptr<void> BlockAddress = getBlockAddress(pEntry);

        if (!BlockAddress) {
            return guest_ptr<void>();
        }

        /* Offset from the table BlockAddress by Offset + 0x4 (First there's a ULONG for size)
         * to get the CM_KEY_NODE */
        const guest_ptr<void> pNodeAddress = BlockAddress + bits.Offset + 0x4;
        return pNodeAddress;
    } catch (TraceableException& ex) {
        /* Sometimes the data isn't available */
        LOG4CXX_WARN(logger, "Exception in CellAddress(): " << ex);
    }

    return guest_ptr<void>();
}

template <typename PtrType>
guest_ptr<void> HIVE_IMPL<PtrType>::getBlockAddress(const guest_ptr<void>& pEntry) const {
    guest_ptr<char[]> hmap_entry_buffer(pEntry, hmap_entry_->size());
    if (hmap_entry_->PermanentBinAddress.exists()) {
        // Win10+
        return pEntry.clone(hmap_entry_->PermanentBinAddress.get<PtrType>(hmap_entry_buffer) &
                            0xfffffffffffffff0LL);
    } else {
        // Older versions
        return pEntry.clone(hmap_entry_->BlockAddress.get<PtrType>(hmap_entry_buffer));
    }
}

template <typename PtrType>
HIVE_IMPL<PtrType>::HIVE_IMPL(const NtKernelImpl<PtrType>& kernel, const guest_ptr<void>& ptr)
    : kernel_(kernel), ptr_(ptr) {

    cmhive_ = LoadOffsets<structs::CMHIVE>(kernel);
    dual_ = LoadOffsets<structs::DUAL>(kernel);
    hmap_entry_ = LoadOffsets<structs::HMAP_ENTRY>(kernel);

    cmhive_buffer_.reset(ptr, cmhive_->size());

    // Verify the signature
    const uint32_t Signature = cmhive_->Hive.Signature.get<uint32_t>(cmhive_buffer_);
    if (unlikely(Signature != 0xbee0bee0)) {
        throw InvalidStructureException("Invalid HIVE signature");
    }
    LOG4CXX_DEBUG(logger, "Parsed HIVE " << ptr);
}

template <typename PtrType>
HIVE_IMPL<PtrType>::~HIVE_IMPL() = default;

template class HIVE_IMPL<uint32_t>;
template class HIVE_IMPL<uint64_t>;

} // namespace nt
} // namespace windows
} /* namespace introvirt */
