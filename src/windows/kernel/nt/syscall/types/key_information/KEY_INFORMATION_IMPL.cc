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
#include "KEY_INFORMATION_IMPL.hh"

#include "KEY_BASIC_INFORMATION_IMPL.hh"
#include "KEY_CACHED_INFORMATION_IMPL.hh"
#include "KEY_FLAGS_INFORMATION_IMPL.hh"
#include "KEY_FULL_INFORMATION_IMPL.hh"
#include "KEY_HANDLE_TAGS_INFORMATION_IMPL.hh"
#include "KEY_NAME_INFORMATION_IMPL.hh"
#include "KEY_NODE_INFORMATION_IMPL.hh"
#include "KEY_VIRTUALIZATION_INFORMATION_IMPL.hh"

#include <introvirt/core/memory/GuestVirtualAddress.hh>
#include <introvirt/windows/kernel/nt/NtKernel.hh>

namespace introvirt {
namespace windows {
namespace nt {

void KEY_INFORMATION_IMPL::write(std::ostream& os, const std::string& linePrefix) const {
    os << linePrefix << "KeyInformationClass: " << KeyInformationClass() << '\n';
}

Json::Value KEY_INFORMATION_IMPL::json() const {
    Json::Value result;
    result["KeyInformationClass"] = to_string(KeyInformationClass());
    return result;
}

template <typename PtrType>
std::unique_ptr<KEY_INFORMATION> make_unique_impl(KEY_INFORMATION_CLASS information_class,
                                                  const GuestVirtualAddress& gva,
                                                  uint32_t buffer_size) {

    // TODO(pape): Implement missing types
    switch (information_class) {
    case KEY_INFORMATION_CLASS::KeyBasicInformation:
        return std::make_unique<KEY_BASIC_INFORMATION_IMPL>(gva, buffer_size);
    case KEY_INFORMATION_CLASS::KeyCachedInformation:
        return std::make_unique<KEY_CACHED_INFORMATION_IMPL>(gva, buffer_size);
    case KEY_INFORMATION_CLASS::KeyFlagsInformation:
        return std::make_unique<KEY_FLAGS_INFORMATION_IMPL>(gva, buffer_size);
    case KEY_INFORMATION_CLASS::KeyFullInformation:
        return std::make_unique<KEY_FULL_INFORMATION_IMPL>(gva, buffer_size);
    case KEY_INFORMATION_CLASS::KeyHandleTagsInformation:
        return std::make_unique<KEY_HANDLE_TAGS_INFORMATION_IMPL>(gva, buffer_size);
    case KEY_INFORMATION_CLASS::KeyNameInformation:
        return std::make_unique<KEY_NAME_INFORMATION_IMPL>(gva, buffer_size);
    case KEY_INFORMATION_CLASS::KeyNodeInformation:
        return std::make_unique<KEY_NODE_INFORMATION_IMPL>(gva, buffer_size);
    case KEY_INFORMATION_CLASS::KeyVirtualizationInformation:
        return std::make_unique<KEY_VIRTUALIZATION_INFORMATION_IMPL>(gva, buffer_size);
    }

    return std::make_unique<KEY_INFORMATION_IMPL>(information_class, gva, buffer_size);
}

std::unique_ptr<KEY_INFORMATION>
KEY_INFORMATION::make_unique(const NtKernel& kernel, KEY_INFORMATION_CLASS information_class,
                             const GuestVirtualAddress& gva, uint32_t buffer_size) {

    if (unlikely(buffer_size == 0))
        return nullptr;

    if (kernel.x64())
        return make_unique_impl<uint64_t>(information_class, gva, buffer_size);
    else
        return make_unique_impl<uint32_t>(information_class, gva, buffer_size);
}

} // namespace nt
} // namespace windows
} // namespace introvirt
