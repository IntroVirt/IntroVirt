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
#include "FILE_ACCESS_INFORMATION_IMPL.hh"

#include <introvirt/core/exception/BufferTooSmallException.hh>
#include <introvirt/util/compiler.hh>

namespace introvirt {
namespace windows {
namespace nt {

void FILE_ACCESS_INFORMATION_IMPL::write(std::ostream& os, const std::string& linePrefix) const {
    os << linePrefix << "FileInformationClass: " << FileInformationClass() << '\n';
    os << linePrefix << "AccessFlags: " << AccessFlags() << '\n';
}

Json::Value FILE_ACCESS_INFORMATION_IMPL::json() const {
    Json::Value result;
    result["FileInformationClass"] = to_string(FileInformationClass());
    result["AccessFlags"] = AccessFlags().json();
    return result;
}

FILE_ACCESS_INFORMATION_IMPL::FILE_ACCESS_INFORMATION_IMPL(const GuestVirtualAddress& gva,
                                                           uint32_t buffer_size)
    : gva_(gva), buffer_size_(buffer_size) {

    if (unlikely(buffer_size < sizeof(structs::_FILE_ACCESS_INFORMATION)))
        throw BufferTooSmallException(sizeof(structs::_FILE_ACCESS_INFORMATION), buffer_size);

    data_.reset(gva_);
}

} // namespace nt
} // namespace windows
} // namespace introvirt