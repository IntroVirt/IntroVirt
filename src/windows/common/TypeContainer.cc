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
#include "TypeContainer.hh"
#include "TypeOffsets.hh"

#include <mutex>

namespace introvirt {
namespace windows {

class TypeContainer::IMPL {
  public:
    std::array<std::unique_ptr<const TypeOffsets>, static_cast<size_t>(TypeID::TYPE_OFFSET_COUNT)>
        type_offsets_;
};

std::unique_ptr<const TypeOffsets>& TypeContainer::get(size_t index) const {
    return pImpl_->type_offsets_[index];
}

void TypeContainer::set(size_t index, std::unique_ptr<TypeOffsets>&& val) const {
    pImpl_->type_offsets_[index] = std::move(val);
}

TypeContainer::TypeContainer() : pImpl_(std::make_unique<IMPL>()) {}

TypeContainer::~TypeContainer() = default;

} // namespace windows
} // namespace introvirt