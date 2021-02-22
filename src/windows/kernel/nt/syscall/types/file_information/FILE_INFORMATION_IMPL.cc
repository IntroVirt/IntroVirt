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
#include "FILE_INFORMATION_IMPL.hh"

#include "FILE_ACCESS_INFORMATION_IMPL.hh"
#include "FILE_ALIGNMENT_INFORMATION_IMPL.hh"
#include "FILE_ALL_INFORMATION_IMPL.hh"
#include "FILE_ATTRIBUTE_TAG_INFORMATION_IMPL.hh"
#include "FILE_BASIC_INFORMATION_IMPL.hh"
#include "FILE_BOTH_DIR_INFORMATION_IMPL.hh"
#include "FILE_DISPOSITION_INFORMATION_IMPL.hh"
#include "FILE_EA_INFORMATION_IMPL.hh"
#include "FILE_END_OF_FILE_INFORMATION_IMPL.hh"
#include "FILE_FULL_DIR_INFORMATION_IMPL.hh"
#include "FILE_ID_BOTH_DIR_INFORMATION_IMPL.hh"
#include "FILE_INTERNAL_INFORMATION_IMPL.hh"
#include "FILE_MODE_INFORMATION_IMPL.hh"
#include "FILE_NAME_INFORMATION_IMPL.hh"
#include "FILE_NETWORK_OPEN_INFORMATION_IMPL.hh"
#include "FILE_POSITION_INFORMATION_IMPL.hh"
#include "FILE_RENAME_INFORMATION_IMPL.hh"
#include "FILE_STANDARD_INFORMATION_IMPL.hh"
#include "FILE_STREAM_INFORMATION_IMPL.hh"

#include <introvirt/windows/kernel/nt/NtKernel.hh>

namespace introvirt {
namespace windows {
namespace nt {

void FILE_INFORMATION_IMPL::write(std::ostream& os, const std::string& linePrefix) const {
    os << linePrefix << "FileInformationClass: " << FileInformationClass() << '\n';
}

Json::Value FILE_INFORMATION_IMPL::json() const {
    Json::Value result;
    result["FileInformationClass"] = to_string(FileInformationClass());
    return result;
}

template <typename PtrType>
std::unique_ptr<FILE_INFORMATION>
make_unique_impl(const NtKernel& kernel, FILE_INFORMATION_CLASS information_class,
                 const GuestVirtualAddress& gva, uint32_t buffer_size) {

    switch (information_class) {
    case FILE_INFORMATION_CLASS::FileAccessInformation:
        return std::make_unique<FILE_ACCESS_INFORMATION_IMPL>(gva, buffer_size);
    case FILE_INFORMATION_CLASS::FileAlignmentInformation:
        return std::make_unique<FILE_ALIGNMENT_INFORMATION_IMPL>(gva, buffer_size);
    case FILE_INFORMATION_CLASS::FileAllInformation:
        return std::make_unique<FILE_ALL_INFORMATION_IMPL>(gva, buffer_size);
    case FILE_INFORMATION_CLASS::FileAttributeTagInformation:
        return std::make_unique<FILE_ATTRIBUTE_TAG_INFORMATION_IMPL>(gva, buffer_size);
    case FILE_INFORMATION_CLASS::FileBasicInformation:
        return std::make_unique<FILE_BASIC_INFORMATION_IMPL>(gva, buffer_size);
    case FILE_INFORMATION_CLASS::FileBothDirectoryInformation:
        return std::make_unique<FILE_BOTH_DIR_INFORMATION_IMPL>(gva, buffer_size);
    case FILE_INFORMATION_CLASS::FileDispositionInformation:
        return std::make_unique<FILE_DISPOSITION_INFORMATION_IMPL>(gva, buffer_size);
    case FILE_INFORMATION_CLASS::FileEaInformation:
        return std::make_unique<FILE_EA_INFORMATION_IMPL>(gva, buffer_size);
    case FILE_INFORMATION_CLASS::FileEndOfFileInformation:
        return std::make_unique<FILE_END_OF_FILE_INFORMATION_IMPL>(gva, buffer_size);
    case FILE_INFORMATION_CLASS::FileFullDirectoryInformation:
        return std::make_unique<FILE_FULL_DIR_INFORMATION_IMPL>(gva, buffer_size);
    case FILE_INFORMATION_CLASS::FileIdBothDirectoryInformation:
        return std::make_unique<FILE_ID_BOTH_DIR_INFORMATION_IMPL>(gva, buffer_size);
    case FILE_INFORMATION_CLASS::FileInternalInformation:
        return std::make_unique<FILE_INTERNAL_INFORMATION_IMPL>(gva, buffer_size);
    case FILE_INFORMATION_CLASS::FileModeInformation:
        return std::make_unique<FILE_MODE_INFORMATION_IMPL>(gva, buffer_size);
    case FILE_INFORMATION_CLASS::FileNameInformation:
        return std::make_unique<FILE_NAME_INFORMATION_IMPL>(gva, buffer_size);
    case FILE_INFORMATION_CLASS::FileNetworkOpenInformation:
        return std::make_unique<FILE_NETWORK_OPEN_INFORMATION_IMPL>(gva, buffer_size);
    case FILE_INFORMATION_CLASS::FilePositionInformation:
        return std::make_unique<FILE_POSITION_INFORMATION_IMPL>(gva, buffer_size);
    case FILE_INFORMATION_CLASS::FileRenameInformation:
        return std::make_unique<FILE_RENAME_INFORMATION_IMPL<PtrType>>(gva, buffer_size);
    case FILE_INFORMATION_CLASS::FileStandardInformation:
        return std::make_unique<FILE_STANDARD_INFORMATION_IMPL>(gva, buffer_size);
    case FILE_INFORMATION_CLASS::FileStreamInformation:
        return std::make_unique<FILE_STREAM_INFORMATION_IMPL>(gva, buffer_size);
    }

    return std::make_unique<FILE_INFORMATION_IMPL>(information_class, gva, buffer_size);
}

std::unique_ptr<FILE_INFORMATION>
FILE_INFORMATION::make_unique(const NtKernel& kernel, FILE_INFORMATION_CLASS information_class,
                              const GuestVirtualAddress& gva, uint32_t buffer_size) {

    if (unlikely(buffer_size == 0))
        return nullptr;

    if (kernel.x64())
        return make_unique_impl<uint64_t>(kernel, information_class, gva, buffer_size);
    else
        return make_unique_impl<uint32_t>(kernel, information_class, gva, buffer_size);
}

} // namespace nt
} // namespace windows
} // namespace introvirt