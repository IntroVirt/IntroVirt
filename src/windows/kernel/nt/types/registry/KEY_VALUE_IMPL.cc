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
#include "KEY_VALUE_IMPL.hh"
#include "KEY_VALUE_DWORD_IMPL.hh"
#include "KEY_VALUE_EXPAND_STRING_IMPL.hh"
#include "KEY_VALUE_MULTI_STRING_IMPL.hh"
#include "KEY_VALUE_QWORD_IMPL.hh"
#include "KEY_VALUE_STRING_IMPL.hh"

namespace introvirt {
namespace windows {
namespace nt {

std::unique_ptr<KEY_VALUE>
KEY_VALUE::make_unique(REG_TYPE regType, const GuestVirtualAddress& pKeyValue, uint32_t dataSize) {
    if (unlikely(dataSize == 0))
        return nullptr;

    switch (regType) {
    case REG_TYPE::REG_DWORD_LITTLE_ENDIAN:
        return std::make_unique<KEY_VALUE_DWORD_IMPL>(pKeyValue, dataSize);
    case REG_TYPE::REG_EXPAND_SZ:
        return std::make_unique<KEY_VALUE_EXPAND_STRING_IMPL>(pKeyValue, dataSize);
    case REG_TYPE::REG_MULTI_SZ:
        return std::make_unique<KEY_VALUE_MULTI_STRING_IMPL>(pKeyValue, dataSize);
    case REG_TYPE::REG_QWORD_LITTLE_ENDIAN:
        return std::make_unique<KEY_VALUE_QWORD_IMPL>(pKeyValue, dataSize);
    case REG_TYPE::REG_SZ:
        return std::make_unique<KEY_VALUE_STRING_IMPL<>>(pKeyValue, dataSize);
    case REG_TYPE::REG_TYPE_UNKNOWN:
    default:
        break;
    }

    return std::make_unique<KEY_VALUE_IMPL<>>(regType, pKeyValue, dataSize);
}

const REG_TYPE KEY_VALUE::RegType(uint32_t type) {
    if (unlikely(type > 11)) {
        return REG_TYPE::REG_TYPE_UNKNOWN;
    }

    return static_cast<REG_TYPE>(type);
}

} /* namespace nt */
} /* namespace windows */
} /* namespace introvirt */
