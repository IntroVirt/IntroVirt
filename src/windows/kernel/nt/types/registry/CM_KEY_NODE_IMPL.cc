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
#include "CM_KEY_NODE_IMPL.hh"
#include "windows/kernel/nt/NtKernelImpl.hh"

#include <introvirt/windows/exception/InvalidStructureException.hh>

#include <log4cxx/logger.h>

#include <memory>

namespace introvirt {
namespace windows {
namespace nt {

static log4cxx::LoggerPtr
    logger(log4cxx::Logger::getLogger("introvirt.windows.kernel.nt.registry.CM_KEY_NODE"));

template <typename PtrType>
const std::string& CM_KEY_NODE_IMPL<PtrType>::Name() const {
    if (Name_.empty()) {
        const uint16_t NameLength = cm_key_node_->NameLength.get<uint16_t>(cm_key_node_buffer_);

        if (Flags() & CM_KEY_NODE::CompressedName) {
            Name_ = guest_ptr<char[]>(ptr_ + cm_key_node_->Name.offset(), NameLength).str();
        } else {
            Name_ = guest_ptr<char16_t[]>(ptr_ + cm_key_node_->Name.offset(),
                                          NameLength / sizeof(char16_t))
                        .str();
        }
    }
    return Name_;
}

template <typename PtrType>
void CM_KEY_NODE_IMPL<PtrType>::addLfLhList(
    const guest_ptr<void>& pList, std::vector<std::unique_ptr<CM_KEY_NODE>>& output) const {

    struct _LF_LH_LIST_ENTRY {
        uint32_t CellIndex;
        union {
            char KeyName[4];
            uint32_t KeyHash;
        };
    };

    guest_ptr<char[]> cm_key_index_buffer(pList, cm_key_index_->size());
    const uint16_t Count = cm_key_index_->Count.get<uint16_t>(cm_key_index_buffer);

    guest_ptr<void> pListEntry = pList + cm_key_index_->List.offset();
    for (uint16_t i = 0; i < Count; ++i) {
        guest_ptr<_LF_LH_LIST_ENTRY> listEntry(pListEntry);
        guest_ptr<void> pChild = hive_.CellAddress(listEntry->CellIndex);
        if (pChild) {
            try {
                output.emplace_back(
                    std::make_unique<CM_KEY_NODE_IMPL<PtrType>>(kernel_, hive_, pChild));
            } catch (TraceableException& ex) {
                LOG4CXX_WARN(logger, "addLfLhList caught exception: " << ex);
            }
        }

        pListEntry += sizeof(_LF_LH_LIST_ENTRY);
    }
}

template <typename PtrType>
void CM_KEY_NODE_IMPL<PtrType>::addLiList(const guest_ptr<void>& pList,
                                          std::vector<std::unique_ptr<CM_KEY_NODE>>& output) const {
    struct _LI_LIST_ENTRY {
        uint32_t CellIndex;
    };

    guest_ptr<char[]> cm_key_index_buffer(pList, cm_key_index_->size());
    const uint16_t Count = cm_key_index_->Count.get<uint16_t>(cm_key_index_buffer);

    guest_ptr<void> pListEntry = pList + cm_key_index_->List.offset();
    for (uint16_t i = 0; i < Count; ++i) {
        guest_ptr<_LI_LIST_ENTRY> listEntry(pListEntry);
        guest_ptr<void> pChild = hive_.CellAddress(listEntry->CellIndex);
        if (pChild) {
            try {
                output.emplace_back(
                    std::make_unique<CM_KEY_NODE_IMPL<PtrType>>(kernel_, hive_, pChild));
            } catch (TraceableException& ex) {
                LOG4CXX_WARN(logger, "addLiList caught exception: " << ex);
            }
        }

        pListEntry += sizeof(_LI_LIST_ENTRY);
    }
}

template <typename PtrType>
void CM_KEY_NODE_IMPL<PtrType>::addRiList(const guest_ptr<void>& pList,
                                          std::vector<std::unique_ptr<CM_KEY_NODE>>& output) const {
    struct _RI_LIST_ENTRY {
        uint32_t CellIndex;
    };

    guest_ptr<char[]> cm_key_index_buffer(pList, cm_key_index_->size());
    const uint16_t Count = cm_key_index_->Count.get<uint16_t>(cm_key_index_buffer);

    guest_ptr<void> pListEntry = pList + cm_key_index_->List.offset();
    for (uint16_t i = 0; i < Count; ++i) {
        guest_ptr<_RI_LIST_ENTRY> listEntry(pListEntry);
        guest_ptr<void> pChildList = hive_.CellAddress(listEntry->CellIndex);
        if (pChildList) {
            try {
                cm_key_index_buffer.reset(pChildList, cm_key_index_->size());
                ;
                switch (cm_key_index_->Signature.get<uint16_t>(cm_key_index_buffer)) {
                case 0x666c: { /* "lf" */
                    addLfLhList(pChildList, output);
                    break;
                }
                case 0x686c: { /* "lh" */
                    addLfLhList(pChildList, output);
                    break;
                }
                case 0x696c: { /* "li" */
                    addLiList(pChildList, output);
                    break;
                }
                }
            } catch (TraceableException& ex) {
                LOG4CXX_WARN(logger, "addRiList caught exception: " << ex);
            }
        }

        pListEntry += sizeof(_RI_LIST_ENTRY);
    }
}

template <typename PtrType>
void CM_KEY_NODE_IMPL<PtrType>::getSubKeys(
    unsigned int listIndex, std::vector<std::unique_ptr<CM_KEY_NODE>>& output) const {

    const uint32_t SubKeyListOffset =
        cm_key_node_->SubKeyLists.offset() + (sizeof(uint32_t) * listIndex);
    const uint32_t SubKeyList =
        *reinterpret_cast<const uint32_t*>(cm_key_node_buffer_.get() + SubKeyListOffset);

    const uint32_t SubKeyCountOffset =
        cm_key_node_->SubKeyCounts.offset() + (sizeof(uint32_t) * listIndex);
    const uint32_t SubKeyCount =
        *reinterpret_cast<const uint32_t*>(cm_key_node_buffer_.get() + SubKeyCountOffset);

    const guest_ptr<void> pList = hive_.CellAddress(SubKeyList);
    if (pList && SubKeyCount) {
        guest_ptr<char[]> cm_key_index_buffer(pList, cm_key_index_->size());
        const uint64_t Signature = cm_key_index_->Signature.get<uint16_t>(cm_key_index_buffer);
        switch (Signature) {
        case 0x666c: { /* "lf" */
            addLfLhList(pList, output);
            break;
        }
        case 0x686c: { /* "lh" */
            addLfLhList(pList, output);
            break;
        }
        case 0x696c: { /* "li" */
            addLiList(pList, output);
            break;
        }
        case 0x6972: { /* "ri" */
            addRiList(pList, output);
            break;
        }
        default:
            break;
        }
    }
}

template <typename PtrType>
const std::vector<std::unique_ptr<CM_KEY_VALUE>>& CM_KEY_NODE_IMPL<PtrType>::Values() const {
    const uint32_t ValueListCount =
        cm_key_node_->ValueList.Count.get<uint32_t>(cm_key_node_buffer_);
    if (Values_.empty() && ValueListCount > 0) {
        struct _VK_LIST_ENTRY {
            uint32_t CellIndex;
        };

        const guest_ptr<void> pList =
            hive_.CellAddress(cm_key_node_->ValueList.List.get<uint32_t>(cm_key_node_buffer_));
        if (pList) {
            guest_ptr<void> pListEntry = pList;
            for (uint16_t i = 0; i < ValueListCount; ++i) {
                guest_ptr<_VK_LIST_ENTRY> listEntry(pListEntry);
                guest_ptr<void> pChild = hive_.CellAddress(listEntry->CellIndex);
                if (pChild) {
                    try {
                        Values_.emplace_back(
                            std::make_unique<CM_KEY_VALUE_IMPL<PtrType>>(kernel_, hive_, pChild));
                    } catch (TraceableException& ex) {
                        LOG4CXX_WARN(logger, "Exception in getValues(): " << ex);
                    }
                }
                pListEntry += sizeof(_VK_LIST_ENTRY);
            }
        }
    }

    return Values_;
}

template <typename PtrType>
const std::vector<std::unique_ptr<CM_KEY_NODE>>& CM_KEY_NODE_IMPL<PtrType>::StableSubKeys() const {
    const uint32_t SubKeyCountOffset = cm_key_node_->SubKeyCounts.offset() + (sizeof(uint32_t) * 0);
    const uint32_t SubKeyCount =
        *reinterpret_cast<const uint32_t*>(cm_key_node_buffer_.get() + SubKeyCountOffset);
    if (stableSubKeys_.empty() && SubKeyCount > 0) {
        getSubKeys(0, stableSubKeys_);
    }
    return stableSubKeys_;
}

template <typename PtrType>
const std::vector<std::unique_ptr<CM_KEY_NODE>>&
CM_KEY_NODE_IMPL<PtrType>::VolatileSubKeys() const {
    const uint32_t SubKeyCountOffset = cm_key_node_->SubKeyCounts.offset() + (sizeof(uint32_t) * 1);
    const uint32_t SubKeyCount =
        *reinterpret_cast<const uint32_t*>(cm_key_node_buffer_.get() + SubKeyCountOffset);
    if (volatileSubKeys_.empty() && SubKeyCount > 0) {
        getSubKeys(1, volatileSubKeys_);
    }
    return volatileSubKeys_;
}

template <typename PtrType>
uint16_t CM_KEY_NODE_IMPL<PtrType>::Flags() const {
    return cm_key_node_->Flags.get<uint16_t>(cm_key_node_buffer_);
}

template <typename PtrType>
CM_KEY_NODE_IMPL<PtrType>::CM_KEY_NODE_IMPL(const NtKernelImpl<PtrType>& kernel,
                                            const HIVE_IMPL<PtrType>& hive,
                                            const guest_ptr<void>& ptr)
    : kernel_(kernel), hive_(hive) {

    cm_key_node_ = LoadOffsets<structs::CM_KEY_NODE>(kernel);
    cm_key_index_ = LoadOffsets<structs::CM_KEY_INDEX>(kernel);

    cm_key_node_buffer_.reset(ptr, cm_key_node_->size());
    ptr_ = ptr;

    const uint16_t Signature = cm_key_node_->Signature.get<uint16_t>(cm_key_node_buffer_);
    if (unlikely(Signature != 0x6b6e)) { // "nk"
        throw InvalidStructureException("Invalid Signature for CM_KEY_NODE");
    }
}

template <typename PtrType>
CM_KEY_NODE_IMPL<PtrType>::~CM_KEY_NODE_IMPL() = default;

template class CM_KEY_NODE_IMPL<uint32_t>;
template class CM_KEY_NODE_IMPL<uint64_t>;

} /* namespace nt */
} /* namespace windows */
} /* namespace introvirt */
