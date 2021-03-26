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
#include <introvirt/windows/kernel/nt/syscall/types/file_information/FILE_ACCESS_INFORMATION.hh>

namespace introvirt {
namespace windows {
namespace nt {

namespace structs {

struct _FILE_ACCESS_INFORMATION {
    uint32_t AccessFlags;
};

} // namespace structs

class FILE_ACCESS_INFORMATION_IMPL final : public FILE_ACCESS_INFORMATION {
  public:
    FILE_ACCESS_MASK AccessFlags() const override { return ptr_->AccessFlags; }

    void AccessFlags(FILE_ACCESS_MASK value) override { ptr_->AccessFlags = value; }

    FILE_INFORMATION_CLASS FileInformationClass() const override {
        return FILE_INFORMATION_CLASS::FileAccessInformation;
    }

    guest_ptr<void> ptr() const override { return ptr_; }

    uint32_t buffer_size() const override { return buffer_size_; }

    void write(std::ostream& os, const std::string& linePrefix = "") const override {
        os << linePrefix << "FileInformationClass: " << FileInformationClass() << '\n';
        os << linePrefix << "AccessFlags: " << AccessFlags() << '\n';
    }

    Json::Value json() const override {
        Json::Value result;
        result["FileInformationClass"] = to_string(FileInformationClass());
        result["AccessFlags"] = AccessFlags().json();
        return result;
    }

    FILE_ACCESS_INFORMATION_IMPL(const guest_ptr<void>& ptr, uint32_t buffer_size)
        : buffer_size_(buffer_size) {

        if (unlikely(buffer_size < sizeof(structs::_FILE_ACCESS_INFORMATION)))
            throw BufferTooSmallException(sizeof(structs::_FILE_ACCESS_INFORMATION), buffer_size);

        ptr_.reset(ptr);
    }

  private:
    guest_ptr<structs::_FILE_ACCESS_INFORMATION> ptr_;
    const uint32_t buffer_size_;
};

} // namespace nt
} // namespace windows
} // namespace introvirt