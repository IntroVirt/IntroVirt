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
#include <memory>
#include <string>

namespace introvirt {
namespace windows {
namespace nt {

class CM_KEY_CONTROL_BLOCK {
  public:
    class KeyFlags {
      public:
        bool KEY_IS_VOLATILE() const;
        bool KEY_HIVE_EXIT() const;
        bool KEY_HIVE_ENTRY() const;
        bool KEY_NO_DELETE() const;
        bool KEY_SYM_LINK() const;
        bool KEY_COMP_NAME() const;
        bool KEY_PREDEF_HANDLE() const;
        bool KEY_VIRT_MIRRORED() const;
        bool KEY_VIRT_TARGET() const;
        bool KEY_VIRTUAL_STORE() const;
        uint16_t value() const { return value_; }

        std::string string(const std::string& separator) const;

        KeyFlags(uint16_t value = 0) : value_(value) {}

      private:
        uint16_t value_;
    };

    class KeyExtFlags {
      public:
        bool CM_KCB_NO_SUBKEY() const;
        bool CM_KCB_SUBKEY_ONE() const;
        bool CM_KCB_SUBKEY_HINT() const;
        bool CM_KCB_SYM_LINK_FOUND() const;
        bool CM_KCB_KEY_NON_EXIST() const;
        bool CM_KCB_NO_DELAY_CLOSE() const;
        bool CM_KCB_INVALID_CACHED_INFO() const;
        bool CM_KCB_READ_ONLY_KEY() const;
        uint16_t value() const { return value_; }

        std::string string(const std::string& separator) const;

        KeyExtFlags(uint16_t value = 0) : value_(value) {}

      private:
        uint16_t value_;
    };

  public:
    /**
     * @returns The parent block for this CM_KEY_CONTROL_BLOCK
     */
    virtual const CM_KEY_CONTROL_BLOCK* ParentKcb() const = 0;

    /**
     * @returns The name of this CM_KEY_CONTROL_BLOCK
     */
    virtual const std::string& Name() const = 0;

    /**
     * @returns The HIVE associated with this key
     */
    virtual const HIVE* KeyHive() const = 0;

    /**
     * @returns The Flags value
     */
    virtual const CM_KEY_CONTROL_BLOCK::KeyFlags Flags() const = 0;

    /**
     * @returns The ExtFlags value
     */
    virtual const CM_KEY_CONTROL_BLOCK::KeyExtFlags ExtFlags() const = 0;

    /**
     * @returns The virtual address of this CM_KEY_CONTROL_BLOCK instance
     */
    virtual GuestVirtualAddress address() const = 0;

    virtual ~CM_KEY_CONTROL_BLOCK() = default;
};

} /* namespace nt */
} /* namespace windows */
} /* namespace introvirt */
