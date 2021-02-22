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
#include "TOKEN_IS_APP_CONTAINER_IMPL.hh"

#include <introvirt/core/exception/BufferTooSmallException.hh>
#include <introvirt/util/compiler.hh>

namespace introvirt {
namespace windows {
namespace nt {

void TOKEN_IS_APP_CONTAINER_IMPL::write(std::ostream& os, const std::string& linePrefix) const {
    TOKEN_IS_APP_CONTAINER_IMPL_BASE::write(os, linePrefix);
    os << linePrefix << "TokenIsAppContainer: " << TokenIsAppContainer() << '\n';
}

Json::Value TOKEN_IS_APP_CONTAINER_IMPL::json() const {
    Json::Value result = TOKEN_IS_APP_CONTAINER_IMPL_BASE::json();
    result["TokenIsAppContainer"] = TokenIsAppContainer();
    return result;
}

TOKEN_IS_APP_CONTAINER_IMPL::TOKEN_IS_APP_CONTAINER_IMPL(const GuestVirtualAddress& gva,
                                                         uint32_t buffer_size)
    : TOKEN_IS_APP_CONTAINER_IMPL_BASE(TOKEN_INFORMATION_CLASS::TokenIsAppContainer, gva,
                                       buffer_size) {}

} // namespace nt
} // namespace windows
} // namespace introvirt