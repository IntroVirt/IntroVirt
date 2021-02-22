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
#include "SECURITY_QUALITY_OF_SERVICE_IMPL.hh"

namespace introvirt {
namespace windows {
namespace nt {

SECURITY_QUALITY_OF_SERVICE_IMPL::SECURITY_QUALITY_OF_SERVICE_IMPL(const GuestVirtualAddress& gva)
    : gva_(gva), data_(gva) {}

std::unique_ptr<SECURITY_QUALITY_OF_SERVICE>
SECURITY_QUALITY_OF_SERVICE::make_unique(const GuestVirtualAddress& gva) {
    return std::make_unique<SECURITY_QUALITY_OF_SERVICE_IMPL>(gva);
}

} // namespace nt
} // namespace windows
} // namespace introvirt