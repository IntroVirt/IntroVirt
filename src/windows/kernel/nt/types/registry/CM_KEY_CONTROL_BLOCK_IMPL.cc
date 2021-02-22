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
#include "CM_KEY_CONTROL_BLOCK_IMPL.hh"
#include "HIVE_IMPL.hh"
#include "windows/kernel/nt/NtKernelImpl.hh"

#include <introvirt/windows/common/WStr.hh>

#include <memory>
#include <sstream>

using namespace std;

namespace introvirt {
namespace windows {
namespace nt {

// CM_KEY_CONTROL_BLOCK::KeyFlags

enum FLAG {
    KEY_IS_VOLATILE = 0x0001,
    KEY_HIVE_EXIT = 0x0002,
    KEY_HIVE_ENTRY = 0x0004,
    KEY_NO_DELETE = 0x0008,
    KEY_SYM_LINK = 0x0010,
    KEY_COMP_NAME = 0x0020,
    KEY_PREDEF_HANDLE = 0x0040,
    KEY_VIRT_MIRRORED = 0x0080,
    KEY_VIRT_TARGET = 0x0100,
    KEY_VIRTUAL_STORE = 0x0200
};

bool CM_KEY_CONTROL_BLOCK::KeyFlags::KEY_IS_VOLATILE() const {
    return value_ & FLAG::KEY_IS_VOLATILE;
}
bool CM_KEY_CONTROL_BLOCK::KeyFlags::KEY_HIVE_EXIT() const { return value_ & FLAG::KEY_HIVE_EXIT; }
bool CM_KEY_CONTROL_BLOCK::KeyFlags::KEY_HIVE_ENTRY() const {
    return value_ & FLAG::KEY_HIVE_ENTRY;
}
bool CM_KEY_CONTROL_BLOCK::KeyFlags::KEY_NO_DELETE() const { return value_ & FLAG::KEY_NO_DELETE; }
bool CM_KEY_CONTROL_BLOCK::KeyFlags::KEY_SYM_LINK() const { return value_ & FLAG::KEY_SYM_LINK; }
bool CM_KEY_CONTROL_BLOCK::KeyFlags::KEY_COMP_NAME() const { return value_ & FLAG::KEY_COMP_NAME; }
bool CM_KEY_CONTROL_BLOCK::KeyFlags::KEY_PREDEF_HANDLE() const {
    return value_ & FLAG::KEY_PREDEF_HANDLE;
}
bool CM_KEY_CONTROL_BLOCK::KeyFlags::KEY_VIRT_MIRRORED() const {
    return value_ & FLAG::KEY_VIRT_MIRRORED;
}
bool CM_KEY_CONTROL_BLOCK::KeyFlags::KEY_VIRT_TARGET() const {
    return value_ & FLAG::KEY_VIRT_TARGET;
}
bool CM_KEY_CONTROL_BLOCK::KeyFlags::KEY_VIRTUAL_STORE() const {
    return value_ & FLAG::KEY_VIRTUAL_STORE;
}

// CM_KEY_CONTROL_BLOCK::KeyExtFlags

enum EXTFLAG {
    CM_KCB_NO_SUBKEY = 0x01,
    CM_KCB_SUBKEY_ONE = 0x02,
    CM_KCB_SUBKEY_HINT = 0x04,
    CM_KCB_SYM_LINK_FOUND = 0x08,
    CM_KCB_KEY_NON_EXIST = 0x10,
    CM_KCB_NO_DELAY_CLOSE = 0x20,
    CM_KCB_INVALID_CACHED_INFO = 0x40,
    CM_KCB_READ_ONLY_KEY = 0x80
};

bool CM_KEY_CONTROL_BLOCK::KeyExtFlags::CM_KCB_NO_SUBKEY() const {
    return value_ & EXTFLAG::CM_KCB_NO_SUBKEY;
}
bool CM_KEY_CONTROL_BLOCK::KeyExtFlags::CM_KCB_SUBKEY_ONE() const {
    return value_ & EXTFLAG::CM_KCB_SUBKEY_ONE;
}
bool CM_KEY_CONTROL_BLOCK::KeyExtFlags::CM_KCB_SUBKEY_HINT() const {
    return value_ & EXTFLAG::CM_KCB_SUBKEY_HINT;
}
bool CM_KEY_CONTROL_BLOCK::KeyExtFlags::CM_KCB_SYM_LINK_FOUND() const {
    return value_ & EXTFLAG::CM_KCB_SYM_LINK_FOUND;
}
bool CM_KEY_CONTROL_BLOCK::KeyExtFlags::CM_KCB_KEY_NON_EXIST() const {
    return value_ & EXTFLAG::CM_KCB_KEY_NON_EXIST;
}
bool CM_KEY_CONTROL_BLOCK::KeyExtFlags::CM_KCB_NO_DELAY_CLOSE() const {
    return value_ & EXTFLAG::CM_KCB_NO_DELAY_CLOSE;
}
bool CM_KEY_CONTROL_BLOCK::KeyExtFlags::CM_KCB_INVALID_CACHED_INFO() const {
    return value_ & EXTFLAG::CM_KCB_INVALID_CACHED_INFO;
}
bool CM_KEY_CONTROL_BLOCK::KeyExtFlags::CM_KCB_READ_ONLY_KEY() const {
    return value_ & EXTFLAG::CM_KCB_READ_ONLY_KEY;
}

// CM_KEY_CONTROL_BLOCK
template <typename PtrType>
const CM_KEY_CONTROL_BLOCK* CM_KEY_CONTROL_BLOCK_IMPL<PtrType>::ParentKcb() const {
    std::lock_guard lock(mtx_);
    if (!parentKCB) {
        const auto pParentKcb =
            gva_.create(cm_key_control_block->ParentKcb.get<PtrType>(cm_key_control_block_buffer));
        if (pParentKcb) {
            parentKCB = std::make_unique<CM_KEY_CONTROL_BLOCK_IMPL<PtrType>>(kernel_, pParentKcb);
        }
    }
    return parentKCB.get();
}

template <typename PtrType>
const std::string& CM_KEY_CONTROL_BLOCK_IMPL<PtrType>::Name() const {
    std::lock_guard lock(mtx_);
    if (name.empty()) {
        // Get the name block
        const auto pNameBlock =
            gva_.create(cm_key_control_block->NameBlock.get<PtrType>(cm_key_control_block_buffer));
        cm_name_control_block_buffer.reset(pNameBlock, cm_name_control_block->size());

        const uint16_t NameLength =
            cm_name_control_block->NameLength.get<uint16_t>(cm_name_control_block_buffer);
        if (NameLength > 0) {
            guest_ptr<uint8_t[]> name(pNameBlock + cm_name_control_block->Name.offset(),
                                      NameLength);
            const bool Compressed =
                cm_name_control_block->Compressed.get<uint8_t>(cm_name_control_block_buffer);

            if (Compressed) {
                this->name = std::string(reinterpret_cast<const char*>(name.get()), NameLength);
            } else {
                this->name = WStr(std::move(name)).utf8();
            }
        }
    }

    return name;
}

template <typename PtrType>
const HIVE* CM_KEY_CONTROL_BLOCK_IMPL<PtrType>::KeyHive() const {
    std::lock_guard lock(mtx_);
    if (!KeyHive_.get()) {
        const auto pKeyHive =
            gva_.create(cm_key_control_block->KeyHive.get<PtrType>(cm_key_control_block_buffer));
        if (pKeyHive) {
            KeyHive_ = std::make_unique<HIVE_IMPL<PtrType>>(kernel_, pKeyHive);
        }
    }
    return KeyHive_.get();
}

template <typename PtrType>
const CM_KEY_CONTROL_BLOCK::KeyFlags CM_KEY_CONTROL_BLOCK_IMPL<PtrType>::Flags() const {
    return CM_KEY_CONTROL_BLOCK::KeyFlags(
        cm_key_control_block->Flags.get<uint16_t>(cm_key_control_block_buffer));
}

template <typename PtrType>
const CM_KEY_CONTROL_BLOCK::KeyExtFlags CM_KEY_CONTROL_BLOCK_IMPL<PtrType>::ExtFlags() const {
    return CM_KEY_CONTROL_BLOCK::KeyExtFlags(
        cm_key_control_block->ExtFlags.get<uint16_t>(cm_key_control_block_buffer));
}

template <typename PtrType>
GuestVirtualAddress CM_KEY_CONTROL_BLOCK_IMPL<PtrType>::address() const {
    return gva_;
}

template <typename PtrType>
CM_KEY_CONTROL_BLOCK_IMPL<PtrType>::CM_KEY_CONTROL_BLOCK_IMPL(const NtKernelImpl<PtrType>& kernel,
                                                              const GuestVirtualAddress& gva)
    : kernel_(kernel), gva_(gva) {

    cm_key_control_block = LoadOffsets<structs::CM_KEY_CONTROL_BLOCK>(kernel);
    cm_name_control_block = LoadOffsets<structs::CM_NAME_CONTROL_BLOCK>(kernel);

    cm_key_control_block_buffer.reset(gva_, cm_key_control_block->size());
}

template <typename PtrType>
CM_KEY_CONTROL_BLOCK_IMPL<PtrType>::~CM_KEY_CONTROL_BLOCK_IMPL() = default;

std::string CM_KEY_CONTROL_BLOCK::KeyFlags::string(const std::string& separator) const {
    std::ostringstream result;

    if (KEY_IS_VOLATILE()) {
        result << "KEY_IS_VOLATILE" << separator;
    }
    if (KEY_HIVE_EXIT()) {
        result << "KEY_HIVE_EXIT" << separator;
    }
    if (KEY_HIVE_ENTRY()) {
        result << "KEY_HIVE_ENTRY" << separator;
    }
    if (KEY_NO_DELETE()) {
        result << "KEY_NO_DELETE" << separator;
    }
    if (KEY_SYM_LINK()) {
        result << "KEY_SYM_LINK" << separator;
    }
    if (KEY_COMP_NAME()) {
        result << "KEY_COMP_NAME" << separator;
    }
    if (KEY_PREDEF_HANDLE()) {
        result << "KEY_PREDEF_HANDLE" << separator;
    }
    if (KEY_VIRT_MIRRORED()) {
        result << "KEY_VIRT_MIRRORED" << separator;
    }
    if (KEY_VIRT_TARGET()) {
        result << "KEY_VIRT_TARGET" << separator;
    }
    if (KEY_VIRTUAL_STORE()) {
        result << "KEY_VIRTUAL_STORE" << separator;
    }

    std::string resultStr = result.str();

    // Remove the trailing separator if one exists
    if (!resultStr.empty() != 0u) {
        return resultStr.substr(0, resultStr.size() - separator.size());
    }

    return resultStr;
}

std::string CM_KEY_CONTROL_BLOCK::KeyExtFlags::string(const std::string& separator) const {
    std::ostringstream result;

    if (CM_KCB_NO_SUBKEY()) {
        result << "CM_KCB_NO_SUBKEY" << separator;
    }
    if (CM_KCB_SUBKEY_ONE()) {
        result << "CM_KCB_SUBKEY_ONE" << separator;
    }
    if (CM_KCB_SUBKEY_HINT()) {
        result << "CM_KCB_SUBKEY_HINT" << separator;
    }
    if (CM_KCB_SYM_LINK_FOUND()) {
        result << "CM_KCB_SYM_LINK_FOUND" << separator;
    }
    if (CM_KCB_KEY_NON_EXIST()) {
        result << "CM_KCB_KEY_NON_EXIST" << separator;
    }
    if (CM_KCB_NO_DELAY_CLOSE()) {
        result << "CM_KCB_NO_DELAY_CLOSE" << separator;
    }
    if (CM_KCB_INVALID_CACHED_INFO()) {
        result << "CM_KCB_INVALID_CACHED_INFO" << separator;
    }
    if (CM_KCB_READ_ONLY_KEY()) {
        result << "CM_KCB_READ_ONLY_KEY" << separator;
    }

    std::string resultStr = result.str();

    // Remove the trailing separator if one exists
    if (!resultStr.empty() != 0u) {
        return resultStr.substr(0, resultStr.size() - separator.size());
    }

    return resultStr;
}

template class CM_KEY_CONTROL_BLOCK_IMPL<uint32_t>;
template class CM_KEY_CONTROL_BLOCK_IMPL<uint64_t>;

} /* namespace nt */
} /* namespace windows */
} /* namespace introvirt */
