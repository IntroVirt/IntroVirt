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
#include "RUNTIME_FUNCTION_IMPL.hh"
#include "IMAGE_EXCEPTION_SECTION_IMPL.hh"

namespace introvirt {
namespace windows {
namespace pe {

const UnwindInfo* RUNTIME_FUNCTION_IMPL::UnwindData() const {
    if (unlikely(is_chained()))
        throw InvalidMethodException();

    if (!UnwindData_) {
        UnwindData_ =
            std::make_unique<UnwindInfoImpl>(section_->image_base_address() + data_->UnwindData);
    }
    return UnwindData_.get();
}

const RUNTIME_FUNCTION* RUNTIME_FUNCTION_IMPL::chained_function() const {
    if (unlikely(!is_chained()))
        throw InvalidMethodException();

    if ((Chained_ == nullptr) && (section_ != nullptr)) {
        Chained_ = section_->get_function_at_rva(data_->UnwindData - 0x01);
    }
    return Chained_;
}

} // namespace pe
} // namespace windows
} // namespace introvirt