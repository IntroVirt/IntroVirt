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
#include "windows/kernel/nt/types/objects/OBJECT_HEADER_IMPL.hh"
#include "windows/kernel/nt/NtKernelImpl.hh"

#include <introvirt/core/exception/InvalidMethodException.hh>
#include <introvirt/windows/kernel/nt/NtKernel.hh>
#include <introvirt/windows/kernel/nt/TypeTable.hh>
#include <introvirt/windows/kernel/nt/types/UNICODE_STRING.hh>

#include <log4cxx/logger.h>

namespace introvirt {
namespace windows {
namespace nt {

static log4cxx::LoggerPtr
    logger(log4cxx::Logger::getLogger("introvirt.windows.kernel.nt.types.OBJECT_HEADER"));

/**
 * @see http://www.codemachine.com/article_objectheader.html
 */
enum class NewHeaderInfoMask : uint8_t {
    OBJECT_HEADER_CREATOR_INFO = 0x01,
    OBJECT_HEADER_NAME_INFO = 0x02,
    OBJECT_HEADER_HANDLE_INFO = 0x04,
    OBJECT_HEADER_QUOTA_INFO = 0x08,
    OBJECT_HEADER_PROCESS_INFO = 0x10,
};

/**
 * @see http://www.informit.com/articles/article.aspx?p=22443
 */
enum OldHeaderObjectFlags {
    OB_FLAG_CREATE_INFO = 0x01,    // has OBJECT_CREATE_INFO
    OB_FLAG_KERNEL_MODE = 0x02,    // created by kernel
    OB_FLAG_CREATOR_INFO = 0x04,   // has OBJECT_CREATOR_INFO
    OB_FLAG_EXCLUSIVE = 0x08,      // OBJ_EXCLUSIVE
    OB_FLAG_PERMANENT = 0x10,      // OBJ_PERMANENT
    OB_FLAG_SECURITY = 0x20,       // has security descriptor
    OB_FLAG_SINGLE_PROCESS = 0x40, // no HandleDBList
    OB_FLAG_DEFER_DELETE = 0x80
};

template <typename PtrType>
GuestVirtualAddress OBJECT_HEADER_IMPL<PtrType>::Body() const {
    return gva_ + offsets_->Body.offset();
}

template <typename PtrType>
const OBJECT_HEADER_CREATOR_INFO& OBJECT_HEADER_IMPL<PtrType>::CreatorInfo() const {
    if (unlikely(!has_creator_info()))
        throw InvalidMethodException();
    if (!creator_info_)
        creator_info_.emplace(kernel_, pcreator_info_);
    return *creator_info_;
}

template <typename PtrType>
const OBJECT_HEADER_HANDLE_INFO& OBJECT_HEADER_IMPL<PtrType>::HandleInfo() const {
    if (unlikely(!has_handle_info()))
        throw InvalidMethodException();
    if (!handle_info_)
        handle_info_.emplace(kernel_, phandle_info_);
    return *handle_info_;
}

template <typename PtrType>
const OBJECT_HEADER_NAME_INFO& OBJECT_HEADER_IMPL<PtrType>::NameInfo() const {
    if (unlikely(!has_name_info()))
        throw InvalidMethodException();
    if (!name_info_)
        name_info_.emplace(kernel_, pname_info_);
    return *name_info_;
}

template <typename PtrType>
const OBJECT_HEADER_PROCESS_INFO& OBJECT_HEADER_IMPL<PtrType>::ProcessInfo() const {
    if (unlikely(!has_process_info()))
        throw InvalidMethodException();
    if (!process_info_)
        process_info_.emplace(kernel_, pprocess_info_);
    return *process_info_;
}

template <typename PtrType>
const OBJECT_HEADER_QUOTA_INFO& OBJECT_HEADER_IMPL<PtrType>::QuotaInfo() const {
    if (unlikely(!has_quota_info()))
        throw InvalidMethodException();
    if (!quota_info_)
        quota_info_.emplace(kernel_, pquota_info_);
    return *quota_info_;
}

template <typename PtrType>
bool OBJECT_HEADER_IMPL<PtrType>::has_creator_info() const {
    return !!pcreator_info_;
}

template <typename PtrType>
bool OBJECT_HEADER_IMPL<PtrType>::has_handle_info() const {
    return !!phandle_info_;
}

template <typename PtrType>
bool OBJECT_HEADER_IMPL<PtrType>::has_name_info() const {
    return !!pname_info_;
}

template <typename PtrType>
bool OBJECT_HEADER_IMPL<PtrType>::has_process_info() const {
    return !!pprocess_info_;
}

template <typename PtrType>
bool OBJECT_HEADER_IMPL<PtrType>::has_quota_info() const {
    return !!quota_info_;
}

template <typename PtrType>
GuestVirtualAddress OBJECT_HEADER_IMPL<PtrType>::address() const {
    return gva_;
}

template <typename PtrType>
ObjectType OBJECT_HEADER_IMPL<PtrType>::type() const {
    return type_;
}

template <typename PtrType>
uint8_t OBJECT_HEADER_IMPL<PtrType>::TypeIndex() const {
    return TypeIndex_;
}

template <typename PtrType>
OBJECT_HEADER_IMPL<PtrType>::OBJECT_HEADER_IMPL(const NtKernelImpl<PtrType>& kernel,
                                                const GuestVirtualAddress& gva)
    : kernel_(kernel), gva_(gva.domain(), (gva.virtual_address() & ~((sizeof(PtrType) * 2LL) - 1)),
                            gva.page_directory()),
      offsets_(LoadOffsets<structs::OBJECT_HEADER>(kernel)) {

    // Virtual address is aligned to 0x8 on 32-bit (0xFFFFFFF8) and 0x10 on 64-bit
    // (0xFFFFFFFFFFFFFFF0) (sizeof(uint32_t) * 2LL) == 0x8 (sizeof(uint64_t) * 2LL) == 0x10

    // Load offsets and map in the structure
    buffer_.reset(gva_, offsets_->size());

    if (offsets_->TypeIndex.exists()) {
        // 6.1+
        const uint8_t InfoMask = offsets_->InfoMask.get<uint8_t>(buffer_);
        GuestVirtualAddress position = this->gva_;

        // Prepare any optional structures

        if (InfoMask & static_cast<uint8_t>(NewHeaderInfoMask::OBJECT_HEADER_CREATOR_INFO)) {
            auto offsets = LoadOffsets<structs::OBJECT_HEADER_CREATOR_INFO>(kernel);
            position -= offsets->size();
            pcreator_info_ = position;
        }

        if (InfoMask & static_cast<uint8_t>(NewHeaderInfoMask::OBJECT_HEADER_NAME_INFO)) {
            auto offsets = LoadOffsets<structs::OBJECT_HEADER_NAME_INFO>(kernel);
            position -= offsets->size();
            pname_info_ = position;
        }

        if (InfoMask & static_cast<uint8_t>(NewHeaderInfoMask::OBJECT_HEADER_HANDLE_INFO)) {
            auto offsets = LoadOffsets<structs::OBJECT_HEADER_HANDLE_INFO>(kernel);
            position -= offsets->size();
            phandle_info_ = position;
        }

        if (InfoMask & static_cast<uint8_t>(NewHeaderInfoMask::OBJECT_HEADER_QUOTA_INFO)) {
            auto offsets = LoadOffsets<structs::OBJECT_HEADER_QUOTA_INFO>(kernel);
            position -= offsets->size();
            pquota_info_ = position;
        }

        if (InfoMask & static_cast<uint8_t>(NewHeaderInfoMask::OBJECT_HEADER_PROCESS_INFO)) {
            auto offsets = LoadOffsets<structs::OBJECT_HEADER_PROCESS_INFO>(kernel);
            position -= offsets->size();
            pprocess_info_ = position;
        }

        TypeIndex_ = offsets_->TypeIndex.get<uint8_t>(buffer_);

        // See if we have to decode the "encrypted" type index.
        // Windows uses a weird Xor thing as a security feature.
        if (kernel.hasObHeaderCookie()) {
            const uint8_t ObHeaderCookie = kernel.ObHeaderCookie();
            const PtrType key = (gva_.virtual_address() >> 8) & 0xFF;
            const uint32_t DecodedTypeIndex = (key ^ ObHeaderCookie ^ TypeIndex_);
            TypeIndex_ = DecodedTypeIndex;
        }

        // Normalize it
        type_ = kernel.types().normalize(TypeIndex_);
    } else {
        // XP
        const uint8_t NameInfoOffset = offsets_->NameInfoOffset.get<uint8_t>(buffer_);
        if (NameInfoOffset) {
            pname_info_ = gva_ - NameInfoOffset;
        }

        const uint8_t Flags = offsets_->Flags.get<uint8_t>(buffer_);
        if (Flags & OB_FLAG_CREATOR_INFO) {
            pcreator_info_ =
                gva_ - LoadOffsets<structs::OBJECT_HEADER_CREATOR_INFO>(kernel)->size();
        }

        // On XP, the Type field is a pointer to the OBJECT_TYPE for the Object.
        // TODO(papes) Finish this!
        const PtrType pType = offsets_->Type.get<PtrType>(buffer_);
        type_ = kernel.types().normalize(gva_.create(pType));
        TypeIndex_ = kernel_.types().native(type_);
    }
}

std::unique_ptr<OBJECT_HEADER> OBJECT_HEADER::make_unique(const NtKernel& kernel,
                                                          const GuestVirtualAddress& gva) {
    if (kernel.x64()) {
        return std::make_unique<OBJECT_HEADER_IMPL<uint64_t>>(
            static_cast<const NtKernelImpl<uint64_t>&>(kernel), gva);
    } else {
        return std::make_unique<OBJECT_HEADER_IMPL<uint32_t>>(
            static_cast<const NtKernelImpl<uint32_t>&>(kernel), gva);
    }
}

template class OBJECT_HEADER_IMPL<uint32_t>;
template class OBJECT_HEADER_IMPL<uint64_t>;

} // namespace nt
} // namespace windows
} // namespace introvirt