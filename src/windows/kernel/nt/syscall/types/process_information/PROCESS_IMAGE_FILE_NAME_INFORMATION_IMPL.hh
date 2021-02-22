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

#include "PROCESS_INFORMATION_IMPL.hh"
#include "windows/kernel/nt/types/UNICODE_STRING_IMPL.hh"

#include <introvirt/util/compiler.hh>
#include <introvirt/windows/common/WStr.hh>
#include <introvirt/windows/exception/InvalidStructureException.hh>
#include <introvirt/windows/kernel/nt/syscall/types/process_information/PROCESS_IMAGE_FILE_NAME_INFORMATION.hh>

#include <optional>

namespace introvirt {
namespace windows {
namespace nt {

namespace structs {

template <typename PtrType>
struct _PROCESS_IMAGE_FILE_NAME_INFORMATION {
    _UNICODE_STRING<PtrType> ImageFileName;
};

} // namespace structs

template <typename PtrType>
using PROCESS_IMAGE_FILE_NAME_INFORMATION_IMPL_BASE =
    PROCESS_INFORMATION_IMPL<PROCESS_IMAGE_FILE_NAME_INFORMATION,
                             structs::_PROCESS_IMAGE_FILE_NAME_INFORMATION<PtrType>>;

template <typename PtrType>
class PROCESS_IMAGE_FILE_NAME_INFORMATION_IMPL
    : public PROCESS_IMAGE_FILE_NAME_INFORMATION_IMPL_BASE<PtrType> {
  public:
    std::string ImageFileName() const final {
        if (ImageFileNameLength_ != this->data_->ImageFileName.Length)
            parse();

        return ImageFileName_->utf8();
    }

    void ImageFileName(const std::string& ImageFileName) final {
        ImageFileName_->set(ImageFileName);
        this->data_->ImageFileName.Length = ImageFileName_->Length();
        ImageFileNameLength_ = ImageFileName_->Length();
    }

    void write(std::ostream& os, const std::string& linePrefix = "") const final;
    Json::Value json() const final;

    PROCESS_IMAGE_FILE_NAME_INFORMATION_IMPL(const GuestVirtualAddress& gva, uint32_t buffer_size);

  protected:
    /*
     * This class handles both ProcessImageFileName and ProcessImageFileNameWin32.
     * That's why it takes the information_class argument.
     */
    PROCESS_IMAGE_FILE_NAME_INFORMATION_IMPL(PROCESS_INFORMATION_CLASS information_class,
                                             const GuestVirtualAddress& gva, uint32_t buffer_size);

  private:
    void parse() const;

    mutable std::optional<UNICODE_STRING_IMPL<PtrType>> ImageFileName_;
    mutable uint16_t ImageFileNameLength_;
};

} // namespace nt
} // namespace windows
} // namespace introvirt