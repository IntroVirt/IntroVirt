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
#include "CM_KEY_VALUE_IMPL.hh"
#include "windows/kernel/nt/NtKernelImpl.hh"

#include <introvirt/windows/common/WStr.hh>
#include <introvirt/windows/exception/InvalidStructureException.hh>
#include <introvirt/windows/kernel/nt/types/registry/KEY_VALUE.hh>
#include <introvirt/windows/kernel/nt/types/registry/KEY_VALUE_DWORD.hh>
#include <introvirt/windows/kernel/nt/types/registry/KEY_VALUE_EXPAND_STRING.hh>
#include <introvirt/windows/kernel/nt/types/registry/KEY_VALUE_MULTI_STRING.hh>
#include <introvirt/windows/kernel/nt/types/registry/KEY_VALUE_QWORD.hh>
#include <introvirt/windows/kernel/nt/types/registry/KEY_VALUE_STRING.hh>

#include <log4cxx/logger.h>

#include <memory>
#include <string>

namespace introvirt {
namespace windows {
namespace nt {

static log4cxx::LoggerPtr
    logger(log4cxx::Logger::getLogger("introvirt.windows.kernel.nt.registry.CM_KEY_VALUE"));

template <typename PtrType>
const std::string& CM_KEY_VALUE_IMPL<PtrType>::Name() const {
    return Name_;
}

template <typename PtrType>
const KEY_VALUE* CM_KEY_VALUE_IMPL<PtrType>::Data() const {
    return Data_.get();
}

template <typename PtrType>
GuestVirtualAddress CM_KEY_VALUE_IMPL<PtrType>::address() const {
    return gva_;
}

template <typename PtrType>
REG_TYPE CM_KEY_VALUE_IMPL<PtrType>::Type() const {
    return KEY_VALUE::RegType(cm_key_value_->Type.get<uint32_t>(cm_key_value_buffer_));
}

template <typename PtrType>
CM_KEY_VALUE_IMPL<PtrType>::CM_KEY_VALUE_IMPL(const NtKernelImpl<PtrType>& kernel,
                                              const HIVE_IMPL<PtrType>& hive,
                                              const GuestVirtualAddress& gva)
    : kernel_(kernel), gva_(gva) {

    cm_key_value_ = LoadOffsets<structs::CM_KEY_VALUE>(kernel);
    cm_key_value_buffer_.reset(gva_, cm_key_value_->size());

    const auto Signature = cm_key_value_->Signature.get<uint16_t>(cm_key_value_buffer_);
    if (unlikely(Signature != 0x6b76)) { // "vk"
        throw InvalidStructureException("Invalid CM_KEY_VALUE signature");
    }

    const auto NameLength = cm_key_value_->NameLength.get<uint16_t>(cm_key_value_buffer_);
    if (NameLength != 0) {
        const GuestVirtualAddress pName = gva_ + cm_key_value_->Name.offset();
        guest_ptr<uint8_t[]> buf(pName, NameLength);
        const uint16_t Flags = cm_key_value_->Flags.get<uint16_t>(cm_key_value_buffer_);
        if (Flags & 0x1) { /* Compressed */
            Name_ = std::string(reinterpret_cast<const char*>(buf.get()), NameLength);
        } else {
            Name_ = WStr(std::move(buf), NameLength).utf8();
        }
    }

    auto DataLength = cm_key_value_->DataLength.get<uint32_t>(cm_key_value_buffer_);
    if (DataLength) {
        GuestVirtualAddress pData;

        if (DataLength & 0x80000000) {
            /* If the MSB of the DataLength field is set, the Data field *IS* the data */
            pData = gva_ + cm_key_value_->Data.offset();

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

template <typename PtrType>
CM_KEY_VALUE_IMPL<PtrType>::~CM_KEY_VALUE_IMPL() = default;

template class CM_KEY_VALUE_IMPL<uint32_t>;
template class CM_KEY_VALUE_IMPL<uint64_t>;

} // namespace nt
} // namespace windows
} /* namespace introvirt */
