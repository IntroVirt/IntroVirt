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

#include <introvirt/windows/kernel/nt/types/registry/CM_KEY_CONTROL_BLOCK.hh>

#include "HIVE_IMPL.hh"
#include "windows/kernel/nt/NtKernelImpl.hh"
#include "windows/kernel/nt/structs/structs.hh"

#include <introvirt/core/memory/guest_ptr.hh>
#include <introvirt/fwd.hh>

#include <mutex>
#include <optional>

namespace introvirt {
namespace windows {
namespace nt {

template <typename PtrType>
class CM_KEY_CONTROL_BLOCK_IMPL final : public CM_KEY_CONTROL_BLOCK {
  public:
    const CM_KEY_CONTROL_BLOCK* ParentKcb() const override {
        std::lock_guard lock(mtx_);
        if (!parentKCB_) {
            const auto pParentKcb = ptr_.clone(
                cm_key_control_block_->ParentKcb.get<PtrType>(cm_key_control_block_buffer_));
            if (pParentKcb) {
                parentKCB_ =
                    std::make_unique<CM_KEY_CONTROL_BLOCK_IMPL<PtrType>>(kernel_, pParentKcb);
            }
        }
        return parentKCB_.get();
    }

    const std::string& Name() const override {
        std::lock_guard lock(mtx_);
        if (name_.empty()) {
            // Get the pointer to the name block
            guest_ptr<void> pNameBlock = ptr_.clone(
                cm_key_control_block_->NameBlock.get<PtrType>(cm_key_control_block_buffer_));

            // Map in the name buffer
            guest_ptr<char[]> cm_name_control_block_buffer(pNameBlock,
                                                           cm_name_control_block_->size());

            const uint16_t NameLength =
                cm_name_control_block_->NameLength.get<uint16_t>(cm_name_control_block_buffer);
            if (NameLength > 0) {
                const bool Compressed =
                    cm_name_control_block_->Compressed.get<uint8_t>(cm_name_control_block_buffer);

                const guest_ptr<void> pNameData =
                    pNameBlock + cm_name_control_block_->Name.offset();

                if (Compressed) {
                    // char
                    name_ = guest_ptr<char[]>(pNameData, NameLength).str();
                } else {
                    // utf16
                    name_ = guest_ptr<char16_t[]>(pNameData, NameLength / sizeof(char16_t)).str();
                }
            }
        }
        return name_;
    }

    const HIVE* KeyHive() const override {
        std::lock_guard lock(mtx_);
        if (!KeyHive_.get()) {
            const auto pKeyHive = ptr_.clone(
                cm_key_control_block_->KeyHive.get<PtrType>(cm_key_control_block_buffer_));
            if (pKeyHive) {
                KeyHive_ = std::make_unique<HIVE_IMPL<PtrType>>(kernel_, pKeyHive);
            }
        }
        return KeyHive_.get();
    }

    const CM_KEY_CONTROL_BLOCK::KeyFlags Flags() const override {
        return CM_KEY_CONTROL_BLOCK::KeyFlags(
            cm_key_control_block_->Flags.get<uint16_t>(cm_key_control_block_buffer_));
    }

    const CM_KEY_CONTROL_BLOCK::KeyExtFlags ExtFlags() const override {
        return CM_KEY_CONTROL_BLOCK::KeyExtFlags(
            cm_key_control_block_->ExtFlags.get<uint16_t>(cm_key_control_block_buffer_));
    }

    const guest_ptr<void>& ptr() const override { return ptr_; }

    CM_KEY_CONTROL_BLOCK_IMPL(const NtKernelImpl<PtrType>& kernel, const guest_ptr<void>& ptr)
        : kernel_(kernel) {

        cm_key_control_block_ = LoadOffsets<structs::CM_KEY_CONTROL_BLOCK>(kernel);
        cm_name_control_block_ = LoadOffsets<structs::CM_NAME_CONTROL_BLOCK>(kernel);

        cm_key_control_block_buffer_.reset(ptr, cm_key_control_block_->size());
        ptr_ = cm_key_control_block_buffer_;
    }

    ~CM_KEY_CONTROL_BLOCK_IMPL() override = default;

  private:
    const NtKernelImpl<PtrType>& kernel_;
    guest_ptr<void> ptr_;
    guest_ptr<char[]> cm_key_control_block_buffer_;

    const structs::CM_KEY_CONTROL_BLOCK* cm_key_control_block_;
    const structs::CM_NAME_CONTROL_BLOCK* cm_name_control_block_;

    mutable std::recursive_mutex mtx_;

    mutable std::unique_ptr<HIVE_IMPL<PtrType>> KeyHive_;
    mutable std::unique_ptr<CM_KEY_CONTROL_BLOCK_IMPL<PtrType>> parentKCB_;

    mutable std::string name_;
};

} // namespace nt
} // namespace windows
} // namespace introvirt