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
#include "UnwindInfoImpl.hh"
#include "IMAGE_EXCEPTION_SECTION_IMPL.hh"
#include "RUNTIME_FUNCTION_IMPL.hh"

namespace introvirt {
namespace windows {
namespace pe {

const RUNTIME_FUNCTION*
UnwindInfoImpl::chained_function(const IMAGE_EXCEPTION_SECTION_IMPL* pdata) const {
    if (pChained_ && !chained_function_) {
        chained_function_ = std::make_unique<RUNTIME_FUNCTION_IMPL>(pdata, pChained_);
    }
    return chained_function_.get();
}

} // namespace pe
} // namespace windows
} // namespace introvirt