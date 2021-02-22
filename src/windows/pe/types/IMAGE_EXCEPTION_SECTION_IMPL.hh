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

#include "IMAGE_SECTION_HEADER_IMPL.hh"
#include "RUNTIME_FUNCTION_IMPL.hh"

#include <introvirt/util/compiler.hh>
#include <introvirt/windows/pe/exception/PeException.hh>
#include <introvirt/windows/pe/types/IMAGE_EXCEPTION_SECTION.hh>

#include <map>

namespace introvirt {
namespace windows {
namespace pe {

// TODO: None of this code is used/tested
class IMAGE_EXCEPTION_SECTION_IMPL final : public IMAGE_EXCEPTION_SECTION {
  public:
    const RUNTIME_FUNCTION* get_function_at_rva(uint32_t rva) const {
        const unsigned int index =
            (rva - exception_section_.value()) / sizeof(structs::_RUNTIME_FUNCTION);

        return functionAtIndex(index);
    }

    const RUNTIME_FUNCTION* get_function_for_rip(uint64_t rip) const {
        // binary search
        int high = count_, low = 0;
        const RUNTIME_FUNCTION* found = nullptr;
        const uint64_t codeOffset = rip - image_base_address_.virtual_address();

        while (low < high && (found == nullptr)) {
            unsigned int index = (high + low) / 2;
            const RUNTIME_FUNCTION* func = functionAtIndex(index);

            if (codeOffset < func->BeginAddress()) {
                high = index;
            } else if (codeOffset > func->EndAddress()) {
                low = index;
            } else {
                found = func;
            }
        }

        return found;
    }

    GuestVirtualAddress image_base_address() const { return image_base_address_; }

    IMAGE_EXCEPTION_SECTION_IMPL(const GuestVirtualAddress& image_base_address,
                                 const GuestVirtualAddress& exception_section, uint32_t size)
        : image_base_address_(image_base_address), exception_section_(exception_section) {

        count_ = size / sizeof(structs::_RUNTIME_FUNCTION);
    }

  private:
    const RUNTIME_FUNCTION* functionAtIndex(unsigned int index) const {
        if (unlikely(index > count_))
            throw PeException("Exception index out of bounds");

        auto iter = cache_.find(index);
        if (iter == cache_.end()) {
            const GuestVirtualAddress pentry =
                exception_section_.value() + (index * sizeof(structs::_RUNTIME_FUNCTION));

            auto result = cache_.try_emplace(index, this, pentry);
            return &(result.first->second);
        } else {
            return &(iter->second);
        }
    }

  private:
    const GuestVirtualAddress image_base_address_;
    const GuestVirtualAddress exception_section_;
    mutable std::map<int, RUNTIME_FUNCTION_IMPL> cache_;
    uint32_t count_;
};

} // namespace pe
} // namespace windows
} // namespace introvirt
