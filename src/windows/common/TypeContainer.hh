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

#include <introvirt/util/compiler.hh>

#include <mspdb/PDB.hh>

#include <memory>
#include <mutex>

namespace introvirt {
namespace windows {

class TypeOffsets;
enum class TypeID : unsigned int;

/**
 * @brief Used internally for guest structure offset information
 */
class TypeContainer {
  public:
    /**
     * @brief Used internally for type information
     *
     * @return The type offsets of the given TypeID
     * @throws TypeInformationException if the type has not been loaded
     */
    template <typename T>
    const T* typeinfo() const;

    /**
     * @brief Check if the guest is 64-bit
     *
     * @return true if the guest is 64-bit
     * @return false if the guest is 32-bit
     */
    virtual bool x64() const = 0;

    /**
     * @brief Get the PDB file for this type container
     *
     * @return The PDB instance
     */
    virtual const mspdb::PDB& pdb() const = 0;

    /**
     * @brief Construct a new instance
     */
    TypeContainer();

    /**
     * @brief Destroy the instance
     */
    virtual ~TypeContainer();

  private:
    std::unique_ptr<const TypeOffsets>& get(size_t index) const;

    void set(size_t index, std::unique_ptr<TypeOffsets>&& val) const;

  private:
    class IMPL;
    std::unique_ptr<IMPL> pImpl_;
    mutable std::mutex mtx_;
};

template <typename T>
const T* TypeContainer::typeinfo() const {
    const auto type_id = static_cast<std::underlying_type_t<TypeID>>(T::ID);

    std::lock_guard lock(mtx_);
    std::unique_ptr<const TypeOffsets>& result = get(type_id);
    if (likely(result.get() != nullptr)) {
        return static_cast<const T*>(result.get());
    }

    // Have to add it
    auto unique_offsets = std::make_unique<T>(*this);
    const T* offsets = unique_offsets.get();
    set(type_id, std::move(unique_offsets));

    return offsets;
}

} // namespace windows
} // namespace introvirt