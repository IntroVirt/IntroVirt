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
#include "CM_KEY_BODY_IMPL.hh"
#include "windows/kernel/nt/NtKernelImpl.hh"

#include <introvirt/windows/exception/InvalidStructureException.hh>
#include <introvirt/windows/kernel/nt/NtKernel.hh>
#include <introvirt/windows/kernel/nt/const/ObjectType.hh>

namespace introvirt {
namespace windows {
namespace nt {

template <typename PtrType>
const std::string& CM_KEY_BODY_IMPL<PtrType>::full_key_path() const {
    std::lock_guard lock(mtx_);
    if (full_path_.empty()) {
        const CM_KEY_CONTROL_BLOCK* ctrlBlock = &KeyControlBlock();
        do {
            // If this flag is enabled, we skip the entry (unless the node has no parent)
            const bool isKeyHiveEntry = ctrlBlock->Flags().KEY_HIVE_ENTRY();
            if (!isKeyHiveEntry || ctrlBlock->ParentKcb() == nullptr) {
                std::string prefix("\\");
                prefix.append(ctrlBlock->Name());
                full_path_ = prefix + full_path_;
            }
            ctrlBlock = ctrlBlock->ParentKcb();
        } while (ctrlBlock != nullptr);
    }
    return full_path_;
}

template <typename PtrType>
const CM_KEY_CONTROL_BLOCK& CM_KEY_BODY_IMPL<PtrType>::KeyControlBlock() const {
    std::lock_guard lock(mtx_);
    if (!KeyControlBlock_) {
        const PtrType pKeyControlBlock = offsets_->KeyControlBlock.get<PtrType>(buffer_);
        if (unlikely(!pKeyControlBlock))
            throw InvalidStructureException("CM_KEY_CONTROL_BLOCK::KeyControlBlock was null");
        KeyControlBlock_ = std::make_unique<CM_KEY_CONTROL_BLOCK_IMPL<PtrType>>(
            kernel_, this->address().create(pKeyControlBlock));
    }
    return *KeyControlBlock_;
}

template <typename PtrType>
uint64_t CM_KEY_BODY_IMPL<PtrType>::ProcessID() const {
    return offsets_->ProcessID.get<PtrType>(buffer_);
}

template <typename PtrType>
CM_KEY_BODY_IMPL<PtrType>::CM_KEY_BODY_IMPL(const NtKernelImpl<PtrType>& kernel,
                                            const GuestVirtualAddress& gva)
    : OBJECT_IMPL<PtrType, CM_KEY_BODY>(kernel, gva, ObjectType::Key), kernel_(kernel),
      offsets_(LoadOffsets<structs::CM_KEY_BODY>(kernel)) {

    buffer_.reset(gva, offsets_->size());
}

template <typename PtrType>
CM_KEY_BODY_IMPL<PtrType>::CM_KEY_BODY_IMPL(
    const NtKernelImpl<PtrType>& kernel,
    std::unique_ptr<OBJECT_HEADER_IMPL<PtrType>>&& object_header)
    : OBJECT_IMPL<PtrType, CM_KEY_BODY>(kernel, std::move(object_header), ObjectType::Key),
      kernel_(kernel), offsets_(LoadOffsets<structs::CM_KEY_BODY>(kernel)) {

    buffer_.reset(OBJECT_IMPL<PtrType, CM_KEY_BODY>::address(), offsets_->size());
}

std::shared_ptr<CM_KEY_BODY> CM_KEY_BODY::make_shared(const NtKernel& kernel,
                                                      const GuestVirtualAddress& gva) {
    if (kernel.x64())
        return std::make_shared<CM_KEY_BODY_IMPL<uint64_t>>(
            static_cast<const NtKernelImpl<uint64_t>&>(kernel), gva);
    else
        return std::make_shared<CM_KEY_BODY_IMPL<uint32_t>>(
            static_cast<const NtKernelImpl<uint32_t>&>(kernel), gva);
}

std::shared_ptr<CM_KEY_BODY>
CM_KEY_BODY::make_shared(const NtKernel& kernel, std::unique_ptr<OBJECT_HEADER>&& object_header) {
    if (kernel.x64()) {
        std::unique_ptr<OBJECT_HEADER_IMPL<uint64_t>> object_header_impl;
        object_header_impl.reset(
            static_cast<OBJECT_HEADER_IMPL<uint64_t>*>(object_header.release()));
        return std::make_shared<CM_KEY_BODY_IMPL<uint64_t>>(
            static_cast<const NtKernelImpl<uint64_t>&>(kernel), std::move(object_header_impl));
    } else {
        std::unique_ptr<OBJECT_HEADER_IMPL<uint32_t>> object_header_impl;
        object_header_impl.reset(
            static_cast<OBJECT_HEADER_IMPL<uint32_t>*>(object_header.release()));
        return std::make_shared<CM_KEY_BODY_IMPL<uint32_t>>(
            static_cast<const NtKernelImpl<uint32_t>&>(kernel), std::move(object_header_impl));
    }
}

template class CM_KEY_BODY_IMPL<uint32_t>;
template class CM_KEY_BODY_IMPL<uint64_t>;

} /* namespace nt */
} /* namespace windows */
} /* namespace introvirt */
