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

#include <introvirt/windows/kernel/nt/types/registry/CM_KEY_VALUE.hh>

#include "HIVE_IMPL.hh"
#include "windows/kernel/nt/NtKernelImpl.hh"
#include "windows/kernel/nt/structs/structs.hh"

#include <introvirt/fwd.hh>
#include <introvirt/windows/exception/InvalidStructureException.hh>
#include <introvirt/windows/kernel/nt/types/registry/KEY_VALUE.hh>
#include <introvirt/windows/kernel/nt/types/registry/KEY_VALUE_DWORD.hh>
#include <introvirt/windows/kernel/nt/types/registry/KEY_VALUE_EXPAND_STRING.hh>
#include <introvirt/windows/kernel/nt/types/registry/KEY_VALUE_MULTI_STRING.hh>
#include <introvirt/windows/kernel/nt/types/registry/KEY_VALUE_QWORD.hh>
#include <introvirt/windows/kernel/nt/types/registry/KEY_VALUE_STRING.hh>

#include <log4cxx/logger.h>

namespace introvirt {
namespace windows {
namespace nt {

template <typename PtrType>
class NtKernelImpl;

template <typename PtrType>
class CM_KEY_VALUE_IMPL final : public CM_KEY_VALUE {
  public:
    const std::string& Name() const override { return Name_; }
    const KEY_VALUE* Data() const override { return Data_.get(); }
    REG_TYPE Type() const override {
        return KEY_VALUE::RegType(cm_key_value_->Type.get<uint32_t>(cm_key_value_buffer_));
    }
    const guest_ptr<void>& ptr() const override { return ptr_; }

    CM_KEY_VALUE_IMPL(const NtKernelImpl<PtrType>& kernel, const HIVE_IMPL<PtrType>& hive,
                      const guest_ptr<void>& ptr)
        : kernel_(kernel), ptr_(ptr) {

        cm_key_value_ = LoadOffsets<structs::CM_KEY_VALUE>(kernel);
        cm_key_value_buffer_.reset(ptr, cm_key_value_->size());
        ptr_ = cm_key_value_buffer_;

        const auto Signature = cm_key_value_->Signature.get<uint16_t>(cm_key_value_buffer_);
        if (unlikely(Signature != 0x6b76)) { // "vk"
            throw InvalidStructureException("Invalid CM_KEY_VALUE signature");
        }

        const auto NameLength = cm_key_value_->NameLength.get<uint16_t>(cm_key_value_buffer_);
        if (NameLength != 0) {
            const uint16_t Flags = cm_key_value_->Flags.get<uint16_t>(cm_key_value_buffer_);
            if (Flags & 0x1) { /* Compressed */
                Name_ =
                    guest_ptr<const char[]>(ptr_ + cm_key_value_->Name.offset(), NameLength).str();
            } else {
                Name_ = guest_ptr<const char16_t[]>(ptr_ + cm_key_value_->Name.offset(),
                                                    NameLength / sizeof(char16_t))
                            .str();
            }
        }

        auto DataLength = cm_key_value_->DataLength.get<uint32_t>(cm_key_value_buffer_);
        if (DataLength) {
            guest_ptr<void> pData;

            if (DataLength & 0x80000000) {
                /* If the MSB of the DataLength field is set, the Data field *IS* the data */
                pData = ptr + cm_key_value_->Data.offset();

                DataLength &= 0x7FFFFFFF;
                if (DataLength > 4) {
                    DataLength = 4;
                } else if (DataLength == 0) {
                    /* No data? */
                    return;
                }
            } else {
                /* Otherwise, we have to lookup the cell */
                auto DataValue = cm_key_value_->Data.get<uint32_t>(cm_key_value_buffer_);
                pData = hive.CellAddress(DataValue);
            }

            if (unlikely(!pData)) {
                /* Can't find the data, just give up */
                return;
            }

            const REG_TYPE type =
                KEY_VALUE::RegType(cm_key_value_->Type.get<uint32_t>(cm_key_value_buffer_));

            Data_ = KEY_VALUE::make_unique(type, pData, DataLength);
        }
    }

    ~CM_KEY_VALUE_IMPL() override = default;

  private:
    const NtKernelImpl<PtrType>& kernel_;
    guest_ptr<void> ptr_;

    const structs::CM_KEY_VALUE* cm_key_value_;
    guest_ptr<char[]> cm_key_value_buffer_;

    std::string Name_;
    std::unique_ptr<KEY_VALUE> Data_;
};

} // namespace nt
} // namespace windows
} // namespace introvirt