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

#include <introvirt/core/memory/GuestVirtualAddress.hh>
#include <introvirt/windows/kernel/nt/fwd.hh>

#include <cstdint>
#include <string>

namespace introvirt {
namespace windows {
namespace nt {

class CM_KEY_NODE;
class HBASE_BLOCK;

class HIVE {
  public:
    enum HiveType {
        HFILE_TYPE_PRIMARY = 0,
        HFILE_TYPE_LOG,
        HFILE_TYPE_EXTERNAL,
    };
    enum HiveFlags {
        HIVE_VOLATILE = 0x1,
        HIVE_NOLAZYFLUSH = 0x2,
        HIVE_HAS_BEEN_REPLACED = 0x4,
        HIVE_HAS_BEEN_FREED = 0x8,
        HIVE_UNKNOWN = 0x10,
        HIVE_UNLOADING = 0x20,
        // TODO(papes): Values seen up to 0x200
    };

    virtual const std::string& FileFullPath() const = 0;
    virtual const std::string& FileUserName() const = 0;
    virtual const std::string& HiveRootPath() const = 0;
    virtual const HBASE_BLOCK& BaseBlock() const = 0;
    virtual const CM_KEY_NODE* RootKeyNode() const = 0;
    virtual const CM_KEY_NODE* KeyNode(uint32_t KeyIndex) const = 0;
    virtual GuestVirtualAddress CellAddress(uint32_t KeyIndex) const = 0;
    virtual const HIVE* PreviousHive() const = 0;
    virtual const HIVE* NextHive() const = 0;
    virtual uint32_t HiveFlags() const = 0;
    virtual GuestVirtualAddress address() const = 0;

    virtual ~HIVE() = default;
};

} /* namespace nt */
} /* namespace windows */
} /* namespace introvirt */
