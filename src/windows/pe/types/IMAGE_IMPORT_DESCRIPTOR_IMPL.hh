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

#include "IMAGE_THUNK_DATA_IMPL.hh"

#include <introvirt/windows/pe/types/IMAGE_IMPORT_DESCRIPTOR.hh>

#include <introvirt/core/memory/guest_ptr.hh>
#include <introvirt/util/compiler.hh>

namespace introvirt {
namespace windows {
namespace pe {

namespace structs {

struct _IMAGE_IMPORT_DESCRIPTOR {
    union {
        uint32_t Characteristics;
        uint32_t OriginalFirstThunk;
    };
    uint32_t TimeDateStamp;
    uint32_t ForwarderChain;
    uint32_t Name;
    uint32_t FirstThunk;
};

} // namespace structs

template <typename PtrType>
class IMAGE_IMPORT_DESCRIPTOR_IMPL final : public IMAGE_IMPORT_DESCRIPTOR {
  public:
    const std::vector<std::unique_ptr<const IMAGE_THUNK_DATA>>& ImportedFunctions() const override {
        {
            std::lock_guard lock(thunks_init_);
            if (thunks_.empty()) {
                GuestVirtualAddress pThunk = image_base_ + data_->OriginalFirstThunk;

                while (true) {
                    // Create a thunk and verify it's not the terminator
                    auto thunk =
                        std::make_unique<IMAGE_THUNK_DATA_IMPL<PtrType>>(image_base_, pThunk);
                    if (thunk->address_of_data() == 0)
                        break;

                    // Push it back on our vector
                    thunks_.push_back(std::move(thunk));

                    // Advance to the next entry
                    pThunk += sizeof(structs::_IMAGE_THUNK_DATA<PtrType>);
                }
            }
        }

        return thunks_;
    }

    IMAGE_IMPORT_DESCRIPTOR_IMPL(const GuestVirtualAddress& image_base,
                                 const GuestVirtualAddress& gva)
        : image_base_(image_base), data_(gva) {

        if (data_->OriginalFirstThunk == 0u)
            return;

        // Get the string
        module_name_ = map_guest_cstr(image_base_ + data_->Name);
    }

  private:
    const GuestVirtualAddress image_base_;
    guest_ptr<structs::_IMAGE_IMPORT_DESCRIPTOR> data_;

    std::mutex thunks_init_;
    mutable std::vector<std::unique_ptr<const IMAGE_THUNK_DATA>> thunks_;

    std::string module_name_;
};

} // namespace pe
} // namespace windows
} // namespace introvirt