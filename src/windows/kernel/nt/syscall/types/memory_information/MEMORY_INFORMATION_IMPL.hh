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

#include <introvirt/core/exception/BufferTooSmallException.hh>
#include <introvirt/core/memory/guest_ptr.hh>
#include <introvirt/util/compiler.hh>
#include <introvirt/windows/kernel/nt/syscall/types/memory_information/MEMORY_INFORMATION.hh>

namespace introvirt {
namespace windows {
namespace nt {

/**
 * @brief Generic base class for memory information
 *
 */
template <typename _BaseClass = MEMORY_INFORMATION, typename _StructType = char>
class MEMORY_INFORMATION_IMPL : public _BaseClass {
  public:
    void write(std::ostream& os, const std::string& linePrefix = "") const override {
        os << linePrefix << "MemoryInformationClass: " << MemoryInformationClass() << '\n';
    }
    Json::Value json() const override {
        Json::Value result;
        result["MemoryInformationClass"] = to_string(MemoryInformationClass());
        return result;
    }

    MEMORY_INFORMATION_CLASS MemoryInformationClass() const override { return class_; }

    guest_ptr<void> ptr() const final { return ptr_; }
    uint32_t buffer_size() const final { return buffer_size_; }

    MEMORY_INFORMATION_IMPL(MEMORY_INFORMATION_CLASS information_class, const guest_ptr<void>& ptr,
                            uint32_t buffer_size)
        : class_(information_class), buffer_size_(buffer_size) {

        if constexpr (!std::is_same_v<_StructType, char>) {
            // Make sure the basic structure fits
            if (unlikely(buffer_size < sizeof(_StructType)))
                throw BufferTooSmallException(sizeof(_StructType), buffer_size);

            // Map it in
            ptr_.reset(ptr);
        }
    }

  protected:
    const MEMORY_INFORMATION_CLASS class_;
    guest_ptr<_StructType> ptr_;
    const uint32_t buffer_size_;
};

} // namespace nt
} // namespace windows
} // namespace introvirt