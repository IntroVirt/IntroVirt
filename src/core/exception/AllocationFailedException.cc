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

#include <introvirt/core/exception/AllocationFailedException.hh>

namespace introvirt {

class AllocationFailedException::IMPL {
  public:
    size_t requested_;
};

size_t AllocationFailedException::requested() const { return pImpl_->requested_; };

AllocationFailedException::AllocationFailedException(size_t requested)
    : TraceableException("Block allocator does not have enough memory: Requested=" +
                         std::to_string(requested)),
      pImpl_(std::make_unique<IMPL>()) {

    pImpl_->requested_ = requested;
}

AllocationFailedException::AllocationFailedException(AllocationFailedException&& src) noexcept =
    default;
AllocationFailedException&
AllocationFailedException::operator=(AllocationFailedException&& src) noexcept = default;
AllocationFailedException::~AllocationFailedException() noexcept = default;

} // namespace introvirt
