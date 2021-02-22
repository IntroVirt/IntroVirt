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

#include <introvirt/windows/kernel/nt/TypeTable.hh>

#include <array>
#include <memory>

namespace introvirt {
namespace windows {
namespace nt {

template <typename PtrType>
class NtKernelImpl;

// Some arbitrary number that we shouldn't ever reach
static constexpr size_t MaxTableSize = 128;

using ToNativeTable = std::array<uint32_t, MaxTableSize>;
using ToNormalizedTable = std::array<ObjectType, MaxTableSize>;
using ObTypeTable = std::array<std::shared_ptr<OBJECT_TYPE>, MaxTableSize>;

template <typename PtrType>
class TypeTableImpl final : public TypeTable {
  public:
    ObjectType normalize(uint32_t type) const override;

    ObjectType normalize(const GuestVirtualAddress& address) const override;

    uint32_t native(ObjectType type) const override;

    const OBJECT_TYPE& type(uint8_t TypeIndex) const;

    TypeTableImpl(const NtKernelImpl<PtrType>& kernel);

  private:
    static constexpr unsigned int JsonVersion = 1;

    bool load_from_json();
    void save_to_json() const;

    int parseObjectTypeTable(const GuestVirtualAddress& pObTypeIndexTable);

    const NtKernelImpl<PtrType>& kernel_;
    ToNativeTable to_native_;
    ToNormalizedTable to_normalized_;
    ObTypeTable type_table_;
    uint32_t table_size_ = 0;

    // OBJECT_TYPE pointer to normalized value
    mutable std::map<uint64_t, ObjectType> xp_to_normalized_;
};

} // namespace nt
} // namespace windows
} // namespace introvirt