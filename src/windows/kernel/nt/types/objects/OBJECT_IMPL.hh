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

#include "OBJECT_HEADER_IMPL.hh"
#include "windows/kernel/nt/structs/structs.hh"

#include <introvirt/util/compiler.hh>
#include <introvirt/windows/exception/IncorrectTypeException.hh>
#include <introvirt/windows/kernel/nt/const/ObjectType.hh>
#include <introvirt/windows/kernel/nt/types/objects/OBJECT.hh>

#include <optional>

namespace introvirt {
namespace windows {
namespace nt {

template <typename PtrType>
class NtKernelImpl;

template <typename PtrType, typename _BaseClass = OBJECT>
class OBJECT_IMPL : public _BaseClass {
  public:
    const OBJECT_HEADER& header() const final { return *header_; }
    guest_ptr<void> ptr() const final { return ptr_; }

    OBJECT_IMPL(const NtKernel& kernel,
                std::unique_ptr<OBJECT_HEADER_IMPL<PtrType>>&& object_header,
                ObjectType expected = ObjectType::Unknown)
        : ptr_(object_header->Body()), header_(std::move(object_header)) {

        if (expected != ObjectType::Unknown) {
            if (unlikely(expected != header().type())) {
                throw IncorrectTypeException("Object is not a " + to_string(expected) + " object");
            }
        }
    }

    OBJECT_IMPL(const NtKernelImpl<PtrType>& kernel, const guest_ptr<void>& ptr,
                ObjectType expected = ObjectType::Unknown)
        : ptr_(ptr), object_header_offsets_(LoadOffsets<structs::OBJECT_HEADER>(kernel)),
          header_(std::make_unique<OBJECT_HEADER_IMPL<PtrType>>(
              kernel, ptr_ - object_header_offsets_->Body.offset())) {

        if (expected != ObjectType::Unknown) {
            if (unlikely(expected != header().type())) {
                throw IncorrectTypeException("Object is not a " + to_string(expected) + " object");
            }
        }
    }

  protected:
    guest_ptr<void> ptr_;

  private:
    const structs::OBJECT_HEADER* object_header_offsets_;

    // This is a unique_ptr so we can take it in by move
    std::unique_ptr<OBJECT_HEADER_IMPL<PtrType>> header_;
};

} // namespace nt
} // namespace windows
} // namespace introvirt