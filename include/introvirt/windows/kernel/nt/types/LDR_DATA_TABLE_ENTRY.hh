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

/**
 * A single entry from the PEB LDR
 */
class LDR_DATA_TABLE_ENTRY {
  public:
    /**
     * @returns The base address of this entry
     */
    virtual GuestVirtualAddress DllBase() const = 0;

    /**
     * @returns The entry point of this entry
     */
    virtual GuestVirtualAddress EntryPoint() const = 0;

    /**
     * @returns The size of this entry
     */
    virtual uint32_t SizeOfImage() const = 0;
    virtual void SizeOfImage(uint32_t value) = 0;

    /**
     * @returns The full dll name of this entry, or NULL if unavailable
     */
    virtual std::string FullDllName() const = 0;
    /**
     * @returns The base dll name of this entry, or NULL if unavailable
     */
    virtual std::string BaseDllName() const = 0;

    virtual ~LDR_DATA_TABLE_ENTRY() = default;
};

} // namespace nt
} // namespace windows
} // namespace introvirt
