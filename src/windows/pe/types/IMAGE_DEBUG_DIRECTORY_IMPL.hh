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

#include "CV_INFO_IMPL.hh"

#include <introvirt/core/memory/guest_ptr.hh>
#include <introvirt/windows/pe/types/IMAGE_DEBUG_DIRECTORY.hh>

#include <optional>

namespace introvirt {
namespace windows {
namespace pe {

namespace structs {

struct _IMAGE_DEBUG_DIRECTORY {
    uint32_t Characteristics;
    uint32_t TimeDateStamp;
    uint16_t MajorVersion;
    uint16_t MinorVersion;
    ImageDebugType Type;
    uint32_t SizeOfData;
    uint32_t AddressOfRawData;
    uint32_t PointerToRawData;
};

} // namespace structs

class IMAGE_DEBUG_DIRECTORY_IMPL final : public IMAGE_DEBUG_DIRECTORY {
  public:
    uint32_t Characteristics() const override { return ptr_->Characteristics; }
    uint32_t TimeDateStamp() const override { return ptr_->TimeDateStamp; }
    uint16_t MajorVersion() const override { return ptr_->MajorVersion; }
    uint16_t MinorVersion() const override { return ptr_->MinorVersion; }
    ImageDebugType Type() const override { return ptr_->Type; }

    const CV_INFO* codeview_data() const override {
        if (cv_info_)
            return &(*cv_info_);
        return nullptr;
    }

    IMAGE_DEBUG_DIRECTORY_IMPL(const guest_ptr<void>& image_base, const guest_ptr<void>& ptr,
                               uint32_t size)
        : ptr_(ptr) {

        switch (Type()) {
        case ImageDebugType::IMAGE_DEBUG_TYPE_CODEVIEW:
            // This is the only one I've actually seen used so far
            cv_info_.emplace(image_base + ptr_->AddressOfRawData, ptr_->SizeOfData);
            break;
        default:
            // Unsupported
            break;
        }
    }

  private:
    guest_ptr<structs::_IMAGE_DEBUG_DIRECTORY> ptr_;
    std::optional<CV_INFO_IMPL> cv_info_;
};

} // namespace pe
} // namespace windows
} // namespace introvirt