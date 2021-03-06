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
#include <introvirt/windows/kernel/nt/syscall/types/token_information/TOKEN_INFORMATION.hh>

namespace introvirt {
namespace windows {
namespace nt {

template <typename _BaseClass = TOKEN_INFORMATION, typename _StructType = char>
class TOKEN_INFORMATION_IMPL : public _BaseClass {
  public:
    TOKEN_INFORMATION_CLASS TokenInformationClass() const final { return class_; }

    guest_ptr<void> ptr() const final { return ptr_; }

    uint32_t buffer_size() const final { return buffer_size_; }

    void write(std::ostream& os, const std::string& linePrefix = "") const override {
        os << linePrefix << "TokenInformationClass: " << TokenInformationClass() << '\n';
    }

    Json::Value json() const override {
        Json::Value result;
        result["TokenInformationClass"] = to_string(TokenInformationClass());
        return result;
    }

    // No length checking version
    TOKEN_INFORMATION_IMPL(TOKEN_INFORMATION_CLASS information_class, const guest_ptr<void>& ptr)
        : class_(information_class) {

        ptr_.reset(ptr);
    }

    TOKEN_INFORMATION_IMPL(TOKEN_INFORMATION_CLASS information_class, const guest_ptr<void>& ptr,
                           uint32_t buffer_size)
        : class_(information_class), buffer_size_(buffer_size) {

        if (unlikely(buffer_size < sizeof(_StructType)))
            throw BufferTooSmallException(sizeof(_StructType), buffer_size);

        ptr_.reset(ptr);
    }

  protected:
    const TOKEN_INFORMATION_CLASS class_;
    guest_ptr<_StructType> ptr_;
    uint32_t buffer_size_; // Not const just for TOKEN_PRIVILEGES_IMPL
};

} // namespace nt
} // namespace windows
} // namespace introvirt